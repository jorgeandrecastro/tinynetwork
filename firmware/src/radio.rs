//! Couche radio : pont entre `esp-radio` (sniffer + injection brute) et les files
//! statiques utilisées par la logique TNP. Aucune allocation côté TNP : trames de
//! taille fixe dans des `Channel` embassy statiques.

use core::cell::Cell;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::channel::Channel;
use esp_radio::wifi::sniffer::{PromiscuousPkt, Sniffer};
use esp_println::println;
use tnp::dot11::{self, MAX_FRAME};
use tnp::{EncodedPacket, Packet};

/// Marge pour le FCS (4 octets) éventuellement présent en fin de trame reçue.
const RX_SLACK: usize = 4;

pub struct RxFrame {
    pub len: usize,
    pub rssi: i32,
    pub data: [u8; MAX_FRAME + RX_SLACK],
}

pub struct TxFrame {
    pub len: usize,
    pub data: [u8; MAX_FRAME],
}

/// Compteur de séquence des paquets que CE nœud crée (les relais conservent le `seq` d'origine).
/// Mutex + `Cell` : le RISC-V `imc` de l'ESP32-C3 n'a pas d'instructions atomiques.
static SEQ: Mutex<CriticalSectionRawMutex, Cell<u16>> = Mutex::new(Cell::new(0));

/// Prochain numéro de séquence (s'enroule à 65535 → 0).
pub fn next_seq() -> u16 {
    SEQ.lock(|c| {
        let v = c.get();
        c.set(v.wrapping_add(1));
        v
    })
}

pub static RX_QUEUE: Channel<CriticalSectionRawMutex, RxFrame, 4> = Channel::new();
pub static TX_QUEUE: Channel<CriticalSectionRawMutex, TxFrame, 4> = Channel::new();

/// Callback promiscuous : appelé par le driver Wi-Fi pour chaque trame captée.
/// Doit rester court : on filtre sur l'Action Frame TNP, on copie, on enfile.
pub fn on_frame(pkt: PromiscuousPkt<'_>) {
    if dot11::unwrap(pkt.data).is_none() {
        return;
    }
    let n = pkt.data.len().min(MAX_FRAME + RX_SLACK);
    let mut frame = RxFrame {
        len: n,
        rssi: pkt.rx_cntl.rssi,
        data: [0u8; MAX_FRAME + RX_SLACK],
    };
    if let (Some(dst), Some(src)) = (frame.data.get_mut(..n), pkt.data.get(..n)) {
        dst.copy_from_slice(src);
        // File pleine : on perd la trame (le mesh est de toute façon best-effort).
        let _ = RX_QUEUE.try_send(frame);
    }
}

/// Encode `pkt`, l'enveloppe dans une Action Frame et l'enfile pour émission.
pub fn send(src_mac: &[u8; 6], pkt: &Packet<'_>) -> Result<(), &'static str> {
    let enc = EncodedPacket::from_packet(pkt).map_err(|_| "encodage TNP")?;
    let mut frame = TxFrame {
        len: 0,
        data: [0u8; MAX_FRAME],
    };
    frame.len = dot11::wrap(src_mac, enc.as_bytes(), &mut frame.data).map_err(|_| "enveloppe 802.11")?;
    TX_QUEUE.try_send(frame).map_err(|_| "file TX pleine")
}

/// Seule tâche à posséder le `Sniffer` : elle vide la file TX et injecte les trames.
#[embassy_executor::task]
pub async fn tx_task(mut sniffer: Sniffer) {
    let mut failures: u32 = 0;
    loop {
        let frame = TX_QUEUE.receive().await;
        let Some(bytes) = frame.data.get(..frame.len) else {
            continue;
        };
        // `true` = interface STA, `true` = numéro de séquence géré par la pile.
        if let Err(e) = sniffer.send_raw_frame(true, bytes, true) {
            failures = failures.wrapping_add(1);
            if failures == 1 || failures % 100 == 0 {
                println!("tx: send_raw_frame a échoué ({:?}), total={}", e, failures);
            }
        }
    }
}