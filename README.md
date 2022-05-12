# ScapyGuard
An extremely bare-bones Python3 WireGuard client.

This is currently a toy - it only implements the initial handshake, and will stop working the moment a rekey is required (after a few minutes). However, you can send and receive packets. Do not use this in production, it is probably insecure, etc. etc.

The current example pings 8.8.8.8.

I think this goes to show how (relatively) simple and elegant WireGuard is as a protocol.

### TODO:

- Proper (async?) state machine for maintaining connections over time, rekeying, *responding* to handshakes, timeouts, etc.

- Replace various security-relevant asserts with proper exception handing and/or state-machine side effects.

- Expose a scapy SuperSocket interface (will probably require putting the state machine in its own thread).

- Implement `mac2`/retry logic in the handshake.

- Maybe implement a server too? (using scapy to send/recv the packets)
