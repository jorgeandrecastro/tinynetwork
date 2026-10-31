# tinyNetwork

Réseau maillé décentralisé pour **ESP32-C3** (Rust `no_std`), basé sur un protocole maison,
**TNP** (*tinyNetwork Protocol*), transporté dans des **trames 802.11 brutes** (Action Frames
vendor-specific). Pas d'ESP-NOW, pas de routeur, pas d'Internet.

```
tinynetwork/
├── tnp/        crate no_std : paquets TNP, CRC16, enveloppe 802.11 (testable sur PC)
└── firmware/   firmware ESP32-C3 : sniffer promiscuous + injection brute + logique mesh
```

## Format TNP

```
[magic 2][ver 1][type 1][ttl 1][src 4][dst 4][len 1][payload 0..=200][crc16 2]
 "TN"      =1      Ping/Pong/Message/…  hops  node id  0xFFFFFFFF = broadcast
```

Big-endian, CRC-16/CCITT-FALSE (poly `0x1021`, init `0xFFFF`) calculé sur l'en-tête + payload.
Enveloppe radio : Action Frame (catégorie 127, OUI `54:4E:50`) diffusée en broadcast.

## 1. Tester le protocole (sur PC)

```bash
cargo test            # à la racine : 11 tests (CRC, aller-retour, corruption, 802.11…)
```

## 2. Compiler et flasher le firmware

Prérequis : Rust stable, la cible RISC-V et `espflash`.

```bash
rustup target add riscv32imc-unknown-none-elf
cargo install espflash

cd firmware
cargo run --release        # compile, flashe et ouvre le moniteur série
```

Flasher **la même image sur chacune des 4 cartes** : l'ID de nœud est dérivé de l'adresse MAC
(4 derniers octets), le canal Wi-Fi est fixé à 6 (`CHANNEL` dans `src/main.rs`).

## 3. Ce que fait le firmware

- capture en mode promiscuous, ne garde que les Action Frames TNP, vérifie magic / version / CRC ;
- Ping broadcast toutes les 5 s (compteur en payload) + Message de démo toutes les 30 s ;
- répond par un Pong unicast à chaque Ping, affiche les Messages ;
- relaie (inondation, TTL − 1) ce qui ne lui est pas destiné, avec un cache anti-doublons
  `(source, CRC16)` de 3 s ;
- `RouteDiscovery` / `RouteReply` / `Ack` : types réservés, **pas encore implémentés**.

Sortie série attendue sur une carte voisine d'une autre :

```
TNP prêt : id=9c4a1f02 mac=… canal=6
rx: Ping src=3b7e55d0 dst=ffffffff ttl=8 rssi=-48dBm len=4
rx: Pong src=3b7e55d0 dst=9c4a1f02 ttl=8 rssi=-48dBm len=4
```

## ⚠️ À valider en premier : l'injection brute sur ESP32-C3

L'émission passe par `esp_wifi_80211_tx` (`Sniffer::send_raw_frame` dans `esp-radio`). Le projet
`esp-csi-rs` rapporte que sur plusieurs puces (ESP32-S3 confirmé, les autres « classic » dont le C3
n'étant pas vérifiés) l'appel renvoie *OK* sans que la trame soit réellement rayonnée. La
réception, elle, fonctionne.

**Test de fumée** : flasher 2 cartes, les placer à quelques mètres, ouvrir les 2 moniteurs.

- lignes `rx: Ping …` des deux côtés → l'injection brute fonctionne sur C3, le mesh peut avancer ;
- uniquement `TNP prêt` et aucun `rx:` (et pas d'erreur `tx:`) → la trame n'est pas rayonnée : il
  faudra changer de vecteur d'émission (voir « Plan B » ci-dessous) ; la couche `tnp` reste valable.

**Plan B** : encapsuler le paquet TNP dans un élément vendor-specific d'une trame de gestion
(beacon / probe request) émise par la pile Wi-Fi ; seul `tnp/src/dot11.rs` et `firmware/src/radio.rs`
changeraient.

## Limites connues

- Le driver Wi-Fi exige un tas (`esp-alloc`, 60 Ko) ; le code TNP lui-même n'alloue pas.
- `esp-radio` est épinglé à `=1.0.0-beta.1` et l'API de sniffer est marquée *unstable*.
- Pas de chiffrement : le CRC16 ne protège que contre la corruption.
- Pas de numéro de séquence dans l'en-tête : dédoublonnage approximatif via le CRC16.

## Licence

GPL-2.0-or-later.
