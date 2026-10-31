# TNP v2 — spécification

| Offset | Taille | Champ | Notes |
|---|---|---|---|
| 0 | 2 | magic | `0x54 0x4E` ("TN") |
| 2 | 1 | version | `2` (les paquets v1, sans `seq`, sont rejetés) |
| 3 | 1 | type | `01` Ping, `02` Pong, `03` Message, `04` RouteDiscovery, `05` RouteReply, `06` Ack |
| 4 | 1 | ttl | décrémenté à chaque relais, relais interdit si ≤ 1 |
| 5 | 4 | src | ID du nœud émetteur d'origine (u32 BE) |
| 9 | 4 | dst | ID destinataire, `0xFFFFFFFF` = broadcast |
| 13 | 2 | seq | compteur par source (u16 BE, s'enroule), **inchangé par les relais** |
| 15 | 1 | len | taille du payload, 0..=200 |
| 16 | len | payload | opaque |
| 16+len | 2 | crc16 | CRC-16/CCITT-FALSE sur les octets `[0 .. 16+len)`, BE |

Taille max d'un paquet : 218 octets.

## Identité d'un paquet et relais

Le couple `(src, seq)` identifie un paquet. Un nœud qui reçoit un `(src, seq)` déjà vu récemment
l'ignore. Un relais ne modifie que le TTL (décrémenté ; pas de relais si TTL ≤ 1).

## Enveloppe 802.11

`[FC=0xD0 0x00][dur 2][DA=ff:ff:ff:ff:ff:ff][SA=MAC STA][BSSID=ff:…][seq 2][cat=127][OUI 54:4E:50][paquet TNP]`

Le FCS est ajouté par le matériel. À la réception, les octets en trop (FCS) sont ignorés.

## Réservé / à définir

Format des payloads RouteDiscovery / RouteReply / Ack, chiffrement.