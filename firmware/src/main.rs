//! tinyNetwork — nœud TNP pour ESP32-C3.
//!
//! - Capture promiscuous des Action Frames TNP et décodage (CRC, TTL, dédoublonnage)
//! - Émission d'un Ping broadcast périodique + d'un Message de démo
//! - Réponse Pong aux Ping, affichage des Messages
//! - Relais par inondation (TTL décrémenté) des paquets qui ne nous sont pas destinés
//!
//! Flasher la même image sur chaque carte : l'ID du nœud est dérivé de l'adresse MAC.

#![no_std]
#![no_main]

mod radio;

use embassy_executor::Spawner;
use embassy_time::{Duration, Instant, Timer};
use esp_hal::clock::CpuClock;
use esp_hal::efuse::{self, InterfaceMacAddress};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config, ControllerConfig, SecondaryChannel, WifiController};
use tnp::{Packet, PacketType, BROADCAST, DEFAULT_TTL};
use {esp_backtrace as _, esp_println as _};

esp_bootloader_esp_idf::esp_app_desc!();

/// Canal Wi-Fi (2.4 GHz) commun à tous les nœuds.
const CHANNEL: u8 = 6;
/// Période du Ping broadcast.
const BEACON_PERIOD: Duration = Duration::from_secs(5);
/// Durée pendant laquelle un paquet déjà vu est ignoré (anti-boucle).
const SEEN_TTL: Duration = Duration::from_secs(3);
const SEEN_SLOTS: usize = 16;

/// Cache circulaire des derniers paquets vus : clé = (source, numéro de séquence).
struct SeenCache {
    slots: [Option<(u32, u16, Instant)>; SEEN_SLOTS],
    next: usize,
}

impl SeenCache {
    const fn new() -> Self {
        Self {
            slots: [None; SEEN_SLOTS],
            next: 0,
        }
    }

    /// Renvoie `true` si le paquet a déjà été vu récemment ; sinon l'enregistre.
    fn seen_before(&mut self, src: u32, seq: u16, now: Instant) -> bool {
        for (s, f, t) in self.slots.iter().flatten() {
            if *s == src && *f == seq && now.duration_since(*t) < SEEN_TTL {
                return true;
            }
        }
        if let Some(slot) = self.slots.get_mut(self.next) {
            *slot = Some((src, seq, now));
        }
        self.next = (self.next + 1) % SEEN_SLOTS;
        false
    }
}

fn halt(msg: &str) -> ! {
    println!("FATAL: {}", msg);
    loop {
        core::hint::spin_loop();
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    // Le driver Wi-Fi a besoin d'un tas ; le code TNP, lui, n'alloue rien.
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 61440);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let mut controller = match WifiController::new(peripherals.WIFI, ControllerConfig::default()) {
        Ok(c) => c,
        Err(_) => halt("init Wi-Fi"),
    };

    // Démarre l'interface STA (sans connexion) puis verrouille le canal.
    if controller
        .set_config(&Config::Station(StationConfig::default()))
        .is_err()
    {
        halt("set_config");
    }
    if controller.set_channel(CHANNEL, SecondaryChannel::None).is_err() {
        halt("set_channel");
    }

    let mut sniffer = controller.sniffer();
    sniffer.set_receive_cb(radio::on_frame);
    if sniffer.set_promiscuous_mode(true).is_err() {
        halt("promiscuous");
    }

    // MAC réellement utilisée par l'interface STA (source des trames injectées).
    let mut mac = [0u8; 6];
    let sta_mac = efuse::interface_mac_address(InterfaceMacAddress::Station);
    if let Some(src) = sta_mac.as_bytes().get(..6) {
        mac.copy_from_slice(src);
    }
    let my_id = u32::from_be_bytes([mac[2], mac[3], mac[4], mac[5]]);
    println!(
        "TNP prêt : id={:08x} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} canal={}",
        my_id, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], CHANNEL
    );

    if let Ok(t) = radio::tx_task(sniffer) {
        spawner.spawn(t);
    }
    if let Ok(t) = rx_task(mac, my_id) {
        spawner.spawn(t);
    }
    if let Ok(t) = beacon_task(mac, my_id) {
        spawner.spawn(t);
    }

    // `controller` doit rester en vie : on le garde ici.
    loop {
        Timer::after(Duration::from_secs(3600)).await;
        let _ = &controller;
    }
}

/// Envoie un Ping broadcast (compteur en payload) toutes les `BEACON_PERIOD`,
/// et un Message de démo toutes les 6 itérations.
#[embassy_executor::task]
async fn beacon_task(mac: [u8; 6], my_id: u32) {
    // Décalage initial dépendant de l'ID pour désynchroniser les nœuds.
    Timer::after(Duration::from_millis(500 + (my_id % 1500) as u64)).await;
    let mut counter: u32 = 0;
    loop {
        let payload = counter.to_be_bytes();
        if let Ok(p) = Packet::new(
            PacketType::Ping,
            DEFAULT_TTL,
            my_id,
            BROADCAST,
            radio::next_seq(),
            &payload,
        ) {
            if let Err(e) = radio::send(&mac, &p) {
                println!("beacon: {}", e);
            }
        }
        if counter % 6 == 5 {
            if let Ok(p) = Packet::new(
                PacketType::Message,
                DEFAULT_TTL,
                my_id,
                BROADCAST,
                radio::next_seq(),
                b"salut depuis TNP",
            ) {
                let _ = radio::send(&mac, &p);
            }
        }
        counter = counter.wrapping_add(1);
        Timer::after(BEACON_PERIOD).await;
    }
}

#[embassy_executor::task]
async fn rx_task(mac: [u8; 6], my_id: u32) {
    let mut seen = SeenCache::new();
    loop {
        let rx = radio::RX_QUEUE.receive().await;
        let Some(frame) = rx.data.get(..rx.len) else {
            continue;
        };
        let Some((_src_mac, body)) = tnp::dot11::unwrap(frame) else {
            continue;
        };
        let pkt = match Packet::decode(body) {
            Ok(p) => p,
            Err(e) => {
                println!("rx: paquet rejeté ({:?})", e);
                continue;
            }
        };
        let h = pkt.header;
        if h.src == my_id {
            continue; // écho de nos propres émissions
        }

        // Doublon (même source, même numéro de séquence) : déjà traité ou relayé.
        if seen.seen_before(h.src, h.seq, Instant::now()) {
            continue;
        }

        println!(
            "rx: {:?} src={:08x} dst={:08x} seq={} ttl={} rssi={}dBm len={}",
            h.ptype, h.src, h.dst, h.seq, h.ttl, rx.rssi, pkt.payload.len()
        );

        let for_me = h.dst == my_id || h.is_broadcast();
        if for_me {
            match h.ptype {
                PacketType::Ping => {
                    // Réponse unicast : on renvoie le payload tel quel.
                    if let Ok(p) = Packet::new(
                        PacketType::Pong,
                        DEFAULT_TTL,
                        my_id,
                        h.src,
                        radio::next_seq(),
                        pkt.payload,
                    ) {
                        let _ = radio::send(&mac, &p);
                    }
                }
                PacketType::Message => match core::str::from_utf8(pkt.payload) {
                    Ok(s) => println!("  message: {}", s),
                    Err(_) => println!("  message binaire ({} octets)", pkt.payload.len()),
                },
                PacketType::Pong => println!("  pong de {:08x}", h.src),
                PacketType::RouteDiscovery | PacketType::RouteReply | PacketType::Ack => {
                    println!("  {:?} : non implémenté", h.ptype);
                }
            }
        }

        // Relais par inondation : tout ce qui n'est pas strictement pour nous.
        if h.dst != my_id {
            if let Some(relayed) = pkt.relayed() {
                // Petit délai pseudo-aléatoire pour limiter les collisions entre relais.
                Timer::after(Duration::from_millis(2 + ((my_id ^ h.seq as u32) % 13) as u64)).await;
                let _ = radio::send(&mac, &relayed);
            }
        }
    }
}