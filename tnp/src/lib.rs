#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! TNP: tinyNetwork Protocol.
//!
//! Format sur le fil (big-endian) :
//! `[magic 2][ver 1][type 1][ttl 1][src 4][dst 4][seq 2][len 1][payload 0..=200][crc16 2]`
//!
//! `seq` est un compteur propre à chaque source, conservé tel quel par les relais : le couple
//! `(src, seq)` identifie un paquet de façon unique (dédoublonnage, accusés de réception).
//!
//! Aucune allocation, aucun `unsafe`, aucun `panic` dans les chemins d'encodage /
//! décodage : toutes les erreurs remontent via [`TnpError`].

pub mod dot11;

pub const MAGIC: [u8; 2] = [0x54, 0x4E]; // "TN"
pub const VERSION: u8 = 2;
pub const BROADCAST: u32 = 0xFFFF_FFFF;

pub const HEADER_LEN: usize = 16;
pub const CRC_LEN: usize = 2;
pub const MAX_PAYLOAD: usize = 200;
pub const MAX_PACKET: usize = HEADER_LEN + MAX_PAYLOAD + CRC_LEN;
pub const DEFAULT_TTL: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TnpError {
    /// Buffer de sortie trop petit.
    BufferTooSmall,
    /// Payload > MAX_PAYLOAD.
    PayloadTooLarge,
    /// Trame plus courte que ce que l'en-tête annonce.
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownType(u8),
    BadChecksum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Ping = 0x01,
    Pong = 0x02,
    Message = 0x03,
    RouteDiscovery = 0x04,
    RouteReply = 0x05,
    Ack = 0x06,
}

impl PacketType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Pong),
            0x03 => Some(Self::Message),
            0x04 => Some(Self::RouteDiscovery),
            0x05 => Some(Self::RouteReply),
            0x06 => Some(Self::Ack),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TnpHeader {
    pub version: u8,
    pub ptype: PacketType,
    pub ttl: u8,
    pub src: u32,
    pub dst: u32,
    pub seq: u16,
    pub payload_len: u8,
}

impl TnpHeader {
    fn write(&self, out: &mut [u8; HEADER_LEN]) {
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = self.version;
        out[3] = self.ptype as u8;
        out[4] = self.ttl;
        out[5..9].copy_from_slice(&self.src.to_be_bytes());
        out[9..13].copy_from_slice(&self.dst.to_be_bytes());
        out[13..15].copy_from_slice(&self.seq.to_be_bytes());
        out[15] = self.payload_len;
    }

    fn parse(b: &[u8; HEADER_LEN]) -> Result<Self, TnpError> {
        if b[0..2] != MAGIC {
            return Err(TnpError::BadMagic);
        }
        if b[2] != VERSION {
            return Err(TnpError::UnsupportedVersion(b[2]));
        }
        let ptype = PacketType::from_u8(b[3]).ok_or(TnpError::UnknownType(b[3]))?;
        if b[15] as usize > MAX_PAYLOAD {
            return Err(TnpError::PayloadTooLarge);
        }
        Ok(Self {
            version: b[2],
            ptype,
            ttl: b[4],
            src: u32::from_be_bytes([b[5], b[6], b[7], b[8]]),
            dst: u32::from_be_bytes([b[9], b[10], b[11], b[12]]),
            seq: u16::from_be_bytes([b[13], b[14]]),
            payload_len: b[15],
        })
    }

    #[inline]
    pub const fn is_broadcast(&self) -> bool {
        self.dst == BROADCAST
    }
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF), calculé bit à bit :
/// aucune table en flash.
pub fn crc16_update(mut crc: u16, data: &[u8]) -> u16 {
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

pub fn crc16(data: &[u8]) -> u16 {
    crc16_update(0xFFFF, data)
}

/// Paquet décodé : le payload emprunte le buffer d'entrée (zero-copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub header: TnpHeader,
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn new(
        ptype: PacketType,
        ttl: u8,
        src: u32,
        dst: u32,
        seq: u16,
        payload: &'a [u8],
    ) -> Result<Self, TnpError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(TnpError::PayloadTooLarge);
        }
        Ok(Self {
            header: TnpHeader {
                version: VERSION,
                ptype,
                ttl,
                src,
                dst,
                seq,
                payload_len: payload.len() as u8, // ≤ 200, cast sans perte
            },
            payload,
        })
    }

    /// Copie du paquet prête à être relayée : TTL décrémenté, `src`/`dst`/`seq` inchangés.
    /// `None` si le TTL est épuisé (≤ 1) : le paquet ne doit plus être relayé.
    pub fn relayed(&self) -> Option<Self> {
        if self.header.ttl <= 1 {
            return None;
        }
        let mut p = *self;
        p.header.ttl -= 1;
        Some(p)
    }

    /// Longueur totale encodée (en-tête + payload + CRC).
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len() + CRC_LEN
    }

    /// Sérialise dans `out`, renvoie le nombre d'octets écrits.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, TnpError> {
        let plen = self.payload.len();
        if plen > MAX_PAYLOAD {
            return Err(TnpError::PayloadTooLarge);
        }
        let total = HEADER_LEN + plen + CRC_LEN;
        let dst = out.get_mut(..total).ok_or(TnpError::BufferTooSmall)?;

        let (head, tail) = dst.split_at_mut(HEADER_LEN);
        let (body, crc_out) = tail.split_at_mut(plen);
        let head: &mut [u8; HEADER_LEN] =
            head.try_into().map_err(|_| TnpError::BufferTooSmall)?;

        let mut header = self.header;
        header.payload_len = plen as u8; // cohérence garantie
        header.write(head);
        body.copy_from_slice(self.payload);

        let crc = crc16_update(crc16(head), body);
        crc_out.copy_from_slice(&crc.to_be_bytes());
        Ok(total)
    }

    /// Désérialise et vérifie magic, version, type, longueur et CRC.
    /// Les octets en trop après le paquet (ex. FCS 802.11) sont ignorés.
    pub fn decode(buf: &'a [u8]) -> Result<Self, TnpError> {
        let head: &[u8; HEADER_LEN] = buf
            .get(..HEADER_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(TnpError::TooShort)?;
        let header = TnpHeader::parse(head)?;

        let payload_end = HEADER_LEN + header.payload_len as usize;
        let payload = buf
            .get(HEADER_LEN..payload_end)
            .ok_or(TnpError::TooShort)?;
        let crc_bytes: [u8; CRC_LEN] = buf
            .get(payload_end..payload_end + CRC_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(TnpError::TooShort)?;

        let expected = crc16_update(crc16(head), payload);
        if u16::from_be_bytes(crc_bytes) != expected {
            return Err(TnpError::BadChecksum);
        }
        Ok(Self { header, payload })
    }
}

/// Paquet encodé sur la pile, prêt à injecter (pas de heap).
#[derive(Clone)]
pub struct EncodedPacket {
    buf: [u8; MAX_PACKET],
    len: usize,
}

impl EncodedPacket {
    pub fn from_packet(p: &Packet<'_>) -> Result<Self, TnpError> {
        let mut buf = [0u8; MAX_PACKET];
        let len = p.encode_into(&mut buf)?;
        Ok(Self { buf, len })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_check_vector() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn roundtrip() {
        let p = Packet::new(PacketType::Message, DEFAULT_TTL, 1, BROADCAST, 42, b"salut").unwrap();
        let enc = EncodedPacket::from_packet(&p).unwrap();
        let dec = Packet::decode(enc.as_bytes()).unwrap();
        assert_eq!(dec, p);
        assert!(dec.header.is_broadcast());
    }

    #[test]
    fn roundtrip_max_payload() {
        let data = [0xA5u8; MAX_PAYLOAD];
        let p = Packet::new(PacketType::Message, 1, 7, 9, 0xFFFF, &data).unwrap();
        let enc = EncodedPacket::from_packet(&p).unwrap();
        assert_eq!(enc.as_bytes().len(), MAX_PACKET);
        assert_eq!(Packet::decode(enc.as_bytes()).unwrap(), p);
    }

    #[test]
    fn rejects_corruption() {
        let p = Packet::new(PacketType::Ping, 3, 1, 2, 0, &[]).unwrap();
        let mut b = [0u8; MAX_PACKET];
        let n = p.encode_into(&mut b).unwrap();
        b[6] ^= 0x01;
        assert_eq!(Packet::decode(&b[..n]), Err(TnpError::BadChecksum));
    }

    #[test]
    fn rejects_truncated_payload() {
        let p = Packet::new(PacketType::Message, 3, 1, 2, 5, b"abcdef").unwrap();
        let mut b = [0u8; MAX_PACKET];
        let n = p.encode_into(&mut b).unwrap();
        assert_eq!(Packet::decode(&b[..n - 1]), Err(TnpError::TooShort));
        assert_eq!(Packet::decode(&b[..HEADER_LEN]), Err(TnpError::TooShort));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Packet::decode(&[0u8; 5]), Err(TnpError::TooShort));
        assert_eq!(Packet::decode(&[0u8; HEADER_LEN + 2]), Err(TnpError::BadMagic));
        assert_eq!(
            Packet::new(PacketType::Message, 1, 1, 2, 0, &[0u8; MAX_PAYLOAD + 1]),
            Err(TnpError::PayloadTooLarge)
        );
        let p = Packet::new(PacketType::Message, 1, 1, 2, 0, b"abc").unwrap();
        let mut small = [0u8; 4];
        assert_eq!(p.encode_into(&mut small), Err(TnpError::BufferTooSmall));
    }

    #[test]
    fn rejects_bad_version_and_type() {
        let p = Packet::new(PacketType::Ping, 3, 1, 2, 0, &[]).unwrap();
        let mut b = [0u8; MAX_PACKET];
        let n = p.encode_into(&mut b).unwrap();

        let mut v = b;
        v[2] = 9;
        assert_eq!(Packet::decode(&v[..n]), Err(TnpError::UnsupportedVersion(9)));

        let mut t = b;
        t[3] = 0xEE;
        assert_eq!(Packet::decode(&t[..n]), Err(TnpError::UnknownType(0xEE)));
    }

    #[test]
    fn seq_is_preserved_on_the_wire() {
        let p = Packet::new(PacketType::Ping, 3, 1, 2, 0xABCD, b"x").unwrap();
        let enc = EncodedPacket::from_packet(&p).unwrap();
        assert_eq!(enc.as_bytes()[13..15], [0xAB, 0xCD]);
        assert_eq!(Packet::decode(enc.as_bytes()).unwrap().header.seq, 0xABCD);
    }

    #[test]
    fn relay_decrements_ttl_and_keeps_identity() {
        let p = Packet::new(PacketType::Message, 3, 11, 22, 77, b"hop").unwrap();
        let r = p.relayed().unwrap();
        assert_eq!(r.header.ttl, 2);
        assert_eq!((r.header.src, r.header.dst, r.header.seq), (11, 22, 77));
        assert_eq!(r.payload, p.payload);
        // TTL épuisé : plus de relais
        let last = Packet::new(PacketType::Message, 1, 11, 22, 77, b"hop").unwrap();
        assert!(last.relayed().is_none());
        let zero = Packet::new(PacketType::Message, 0, 11, 22, 77, b"hop").unwrap();
        assert!(zero.relayed().is_none());
    }

    #[test]
    fn rejects_v1_packets() {
        // Un paquet « v1 » (en-tête 14 octets, version 1) ne doit pas être accepté.
        let mut b = [0u8; MAX_PACKET];
        b[0..2].copy_from_slice(&MAGIC);
        b[2] = 1;
        b[3] = PacketType::Ping as u8;
        assert_eq!(Packet::decode(&b[..HEADER_LEN + CRC_LEN]), Err(TnpError::UnsupportedVersion(1)));
    }

    #[test]
    fn ignores_trailing_bytes() {
        let p = Packet::new(PacketType::Ping, 3, 1, 2, 0, b"x").unwrap();
        let mut b = [0u8; MAX_PACKET + 4];
        let n = p.encode_into(&mut b).unwrap();
        assert_eq!(Packet::decode(&b[..n + 4]).unwrap(), p);
    }
}