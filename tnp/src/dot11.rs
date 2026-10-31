//! Encapsulation d'un paquet TNP dans une Action Frame 802.11 (catégorie vendor-specific).
//!
//! `[FC 2][dur 2][DA 6][SA 6][BSSID 6][seq 2][cat=127][OUI 3][paquet TNP]`
//!
//! Le FCS (4 octets) est ajouté par le matériel à l'émission ; à la réception, il peut
//! traîner en fin de trame : `Packet::decode` ignore les octets en trop.

use crate::MAX_PACKET;

pub const MAC_HDR_LEN: usize = 24;
pub const CATEGORY_VENDOR: u8 = 127;
/// OUI propre à TNP ("TNP"), volontairement différent de celui d'ESP-NOW.
pub const TNP_OUI: [u8; 3] = [0x54, 0x4E, 0x50];
pub const BODY_OFFSET: usize = MAC_HDR_LEN + 1 + 3;
pub const MAX_FRAME: usize = BODY_OFFSET + MAX_PACKET;
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dot11Error {
    BufferTooSmall,
    PayloadTooLarge,
}

/// Écrit la trame complète dans `out`, renvoie sa longueur.
pub fn wrap(src_mac: &[u8; 6], tnp: &[u8], out: &mut [u8]) -> Result<usize, Dot11Error> {
    if tnp.len() > MAX_PACKET {
        return Err(Dot11Error::PayloadTooLarge);
    }
    let total = BODY_OFFSET + tnp.len();
    let o = out.get_mut(..total).ok_or(Dot11Error::BufferTooSmall)?;

    o[0] = 0xD0; // management, subtype Action
    o[1] = 0x00;
    o[2..4].copy_from_slice(&[0, 0]); // duration
    o[4..10].copy_from_slice(&BROADCAST_MAC); // DA
    o[10..16].copy_from_slice(src_mac); // SA
    o[16..22].copy_from_slice(&BROADCAST_MAC); // BSSID
    o[22..24].copy_from_slice(&[0, 0]); // seq (géré par la pile si use_internal_seq_num)
    o[24] = CATEGORY_VENDOR;
    o[25..28].copy_from_slice(&TNP_OUI);
    o[BODY_OFFSET..].copy_from_slice(tnp);
    Ok(total)
}

/// Si la trame est une Action TNP, renvoie (MAC source, octets du paquet TNP).
pub fn unwrap(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    let h = frame.get(..BODY_OFFSET)?;
    if h[0] != 0xD0 || h[24] != CATEGORY_VENDOR || h[25..28] != TNP_OUI {
        return None;
    }
    let mut src = [0u8; 6];
    src.copy_from_slice(&h[10..16]);
    Some((src, frame.get(BODY_OFFSET..)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncodedPacket, Packet, PacketType, BROADCAST};

    #[test]
    fn wrap_unwrap_roundtrip() {
        let p = Packet::new(PacketType::Ping, 4, 7, BROADCAST, b"hi").unwrap();
        let enc = EncodedPacket::from_packet(&p).unwrap();
        let mac = [2, 0, 0, 0, 0, 1];

        let mut f = [0u8; MAX_FRAME + 4];
        let n = wrap(&mac, enc.as_bytes(), &mut f).unwrap();
        // simule un FCS de 4 octets en fin de trame reçue
        let (src, body) = unwrap(&f[..n + 4]).unwrap();
        assert_eq!(src, mac);
        assert_eq!(Packet::decode(body).unwrap(), p);
    }

    #[test]
    fn ignores_foreign_frames() {
        assert!(unwrap(&[0u8; 10]).is_none());
        assert!(unwrap(&[0u8; BODY_OFFSET + 5]).is_none());
    }

    #[test]
    fn wrap_rejects_small_buffer() {
        let mut small = [0u8; 10];
        assert_eq!(wrap(&[0; 6], b"abc", &mut small), Err(Dot11Error::BufferTooSmall));
    }
}
