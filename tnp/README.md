# tnp

[![Crates.io](https://img.shields.io/crates/v/tnp.svg)](https://crates.io/crates/tnp)
[![Downloads](https://img.shields.io/crates/d/tnp.svg)](https://crates.io/crates/tnp)
[![docs.rs](https://docs.rs/tnp/badge.svg)](https://docs.rs/tnp)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)

`no_std`, allocation-free implementation of **TNP** (tinyNetwork Protocol), a compact packet format
for mesh networking over raw 802.11 frames on microcontrollers.

## Features

- Fixed 16-byte header (including a per-source sequence number), payload up to 200 bytes, CRC-16/CCITT-FALSE trailer
- Explicit big-endian (de)serialization: no `unsafe`, no `repr(packed)`, no panics on malformed input
- Zero-copy decoding (`Packet<'a>` borrows the receive buffer)
- 802.11 Action Frame wrapping/unwrapping (`dot11` module), vendor-specific category with a dedicated OUI

## Wire format

```
[magic 2][ver 1][type 1][ttl 1][src 4][dst 4][seq 2][len 1][payload 0..=200][crc16 2]
```

## Example

```rust
use tnp::{EncodedPacket, Packet, PacketType, BROADCAST, DEFAULT_TTL};

let pkt = Packet::new(PacketType::Message, DEFAULT_TTL, 1, BROADCAST, 0, b"hello")?;
let enc = EncodedPacket::from_packet(&pkt)?;
let back = Packet::decode(enc.as_bytes())?;
assert_eq!(back, pkt);
# Ok::<(), tnp::TnpError>(())
```

## License

GPL-2.0-or-later.