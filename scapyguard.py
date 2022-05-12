from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
import base64
import hashlib
import struct
import socket
import time

#from scapy.config import conf
#conf.use_pcap = True
from scapy.all import IP
from scapy.contrib.wireguard import Wireguard, WireguardInitiation, WireguardTransport

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER   = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1   = b"mac1----"
LABEL_COOKIE = b"cookie--"


def HASH(data):
	digest = hashes.Hash(hashes.BLAKE2s(32))
	digest.update(data)
	return digest.finalize()

def HMAC(key, data):
	h = hmac.HMAC(key, hashes.BLAKE2s(32))
	h.update(data)
	return h.finalize()

def MAC(key, data):
	return hashlib.blake2s(data, digest_size=16, key=key).digest() # cryptography.io does not yet support keyed hashing

def AEAD(key, ctr, msg, authtxt=b""):
	nonce = bytes(4) + ctr.to_bytes(8, "little")
	return ChaCha20Poly1305(key).encrypt(nonce, msg, authtxt)

def AEAD_dec(key, ctr, data, authtxt=b""):
	nonce = bytes(4) + ctr.to_bytes(8, "little")
	return ChaCha20Poly1305(key).decrypt(nonce, data, authtxt)

def TAI64N(): # todo: check that this is vaguely correct
	timestamp = time.time()
	seconds = int(timestamp) + (2 ** 62) + 10
	nanoseconds = int((timestamp % 1) * 1e6)
	return struct.pack(">QI", seconds, nanoseconds)

def pub_bytes(pubkey):
	return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

class WireguardSession:
	def __init__(self, config):
		self.config = config
		self.connect()
		self.initiate_handshake()
	
	def log(self, msg, marker="*"):
		if 1:
			print(f"[{marker}] {msg}")

	def connect(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
		self.sock.connect((self.config.SERVER_ADDR, self.config.SERVER_PORT))

	def initiate_handshake(self):
		client_privkey = X25519PrivateKey.from_private_bytes(base64.b64decode(self.config.CLIENT_PRIVKEY))
		server_pubkey = X25519PublicKey.from_public_bytes(base64.b64decode(self.config.SERVER_PUBKEY))

		chaining_key = HASH(CONSTRUCTION)
		hash = HASH(HASH(chaining_key + IDENTIFIER) + pub_bytes(server_pubkey))
		ephemeral_private = X25519PrivateKey.generate()

		req = Wireguard()/WireguardInitiation()
		self.client_index = 1 # TODO
		req.payload.sender_index = self.client_index

		req.payload.unencrypted_ephemeral = pub_bytes(ephemeral_private.public_key())
		hash = HASH(hash + req.payload.unencrypted_ephemeral)

		temp = HMAC(chaining_key, req.payload.unencrypted_ephemeral)
		chaining_key = HMAC(temp, b"\x01")

		temp = HMAC(chaining_key, ephemeral_private.exchange(server_pubkey))
		chaining_key = HMAC(temp, b"\x01")
		key = HMAC(temp, chaining_key + b"\x02")

		req.payload.encrypted_static = AEAD(key, 0, pub_bytes(client_privkey.public_key()), hash)
		hash = HASH(hash + req.payload.encrypted_static)

		temp = HMAC(chaining_key, client_privkey.exchange(server_pubkey))
		chaining_key = HMAC(temp, b"\x01")
		key = HMAC(temp, chaining_key + b"\x02")

		req.payload.encrypted_timestamp = AEAD(key, 0, TAI64N(), hash)
		hash = HASH(hash + req.payload.encrypted_timestamp)

		req.payload.mac1 = MAC(HASH(LABEL_MAC1 + pub_bytes(server_pubkey)), bytes(req)[:-32])
		req.payload.mac2 = bytes(16) # TODO

		self.log("req: " + repr(req))

		self.sock.send(bytes(req))
		res_bytes = self.sock.recv(4096) # TODO: sensible timeout
		res = Wireguard(res_bytes)

		self.log("res:", repr(res))

		assert(res.message_type == 2)
		assert(res.reserved_zero == 0)
		assert(res.payload.receiver_index == self.client_index)
		mac1_target = MAC(HASH(LABEL_MAC1 + pub_bytes(client_privkey.public_key())), bytes(res)[:12+32+16])
		assert(res.payload.mac1 == mac1_target)
		assert(res.payload.mac2 == bytes(16))

		server_ephemeral_pub = X25519PublicKey.from_public_bytes(res.payload.unencrypted_ephemeral)

		hash = HASH(hash + res.payload.unencrypted_ephemeral)

		temp = HMAC(chaining_key, res.payload.unencrypted_ephemeral)
		chaining_key = HMAC(temp, b"\x01")

		temp = HMAC(chaining_key, ephemeral_private.exchange(server_ephemeral_pub))
		chaining_key = HMAC(temp, b"\x01")

		temp = HMAC(chaining_key, client_privkey.exchange(server_ephemeral_pub))
		chaining_key = HMAC(temp, b"\x01")

		preshared_key = bytes(32)
		temp = HMAC(chaining_key, preshared_key)
		chaining_key = HMAC(temp, b"\x01")

		temp2 = HMAC(temp, chaining_key + b"\x02")
		key = HMAC(temp, temp2 + b"\x03")
		hash = HASH(hash + temp2)

		nothing = AEAD_dec(key, 0, res.payload.encrypted_nothing, hash)
		assert(nothing == b"")
		self.server_index = res.payload.sender_index

		hash = HASH(hash + res.payload.encrypted_nothing)

		temp1 = HMAC(chaining_key, b"")
		temp2 = HMAC(temp1, b"\x01")
		temp3 = HMAC(temp1, temp2 + b"\x02")
		self.sending_key = temp2
		self.receiving_key = temp3
		self.sending_key_counter = 0
		self.receiving_key_counter = -1 # TODO: verify

		self.log("sending_key: " + self.sending_key.hex())
		self.log("receiving_key: " + self.receiving_key.hex())
	
	def send(self, data):
		data = bytes(data)
		padded = data + bytes(-len(data)%16)
		self.log("packet to send: " + repr(IP(padded)))
		pkt = Wireguard()/WireguardTransport(
			receiver_index=self.server_index,
			counter=self.sending_key_counter,
			encrypted_encapsulated_packet=AEAD(self.sending_key, self.sending_key_counter, padded)
		)
		self.sending_key_counter += 1
		self.log("sending: " + repr(pkt))
		self.sock.send(bytes(pkt))
	
	def recv(self):
		pkt = Wireguard(self.sock.recv(4096))
		self.log("received: " + repr(pkt))

		assert(pkt.message_type == 4)
		assert(pkt.payload.counter > self.receiving_key_counter)
		body = AEAD_dec(self.receiving_key, pkt.payload.counter, pkt.payload.encrypted_encapsulated_packet)
		self.receiving_key_counter = pkt.payload.counter
		return body
