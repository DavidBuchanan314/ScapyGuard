from scapy.all import IP, ICMP
from scapyguard import WireguardSession
import config
import time

wg = WireguardSession(config)

seq = 0
while True:
	# ping 8.8.8.8
	wg.send(bytes(IP(src=config.IP, dst="8.8.8.8")/ICMP(seq=seq)))

	# print the next packet we receive (hopefully a reply!)
	print(repr(IP(wg.recv())))

	time.sleep(1)
	seq += 1
