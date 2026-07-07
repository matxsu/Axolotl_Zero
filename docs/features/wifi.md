# Wi-Fi — 2.4 GHz (ESP32-S3 natif)

> État au 4 juillet 2026 (branche `feature/unify`). AP + file browser **validés** ;
> les attaques (scan, sniff/deauth, evil twin) sont **implémentées** mais leur
> démo matérielle reste à valider. Drivers : `axolotl-fw/src/wifi/` — `mod.rs`
> (AP + HTTP), `scan.rs`, `sniff.rs`, `eviltwin.rs`, `portals.rs`,
> `captive_dns.rs`. Attaques portées depuis `feature/wifi_attacks`.

## Matériel

- **Radio Wi-Fi 2.4 GHz intégrée** à l'ESP32-S3 — aucun composant externe.
- **2.4 GHz uniquement** (pas de 5 GHz sur l'ESP32-S3).
- Le `modem` est **emprunté** par chaque écran puis rendu à l'appelant, pour
  passer d'un outil à l'autre sans reboot.

## Fonctionnalités implémentées

Menu **WiFi Tools** : `Scan reseaux`, `Evil twin`, `Sniff / Deauth`,
`File browser`, `Creds captures`.

| Capacité | État | Notes |
|---|---|---|
| **AP + file browser web** | ✅ | SoftAP `AxolotlZero` (pass `axolotl1`), serveur HTTP sur `192.168.71.1`, interface embarquée (`index.html`), navigation/download/upload de `/sdcard` |
| **Scan réseaux** | ⚠️ | Mode station, liste SSID/RSSI/canal (`scan.rs`) |
| **Sniff / Deauth + handshake WPA** | ⚠️ | Promiscuous 802.11, détection EAPOL, sauvegarde du handshake en **`.pcap`** sur SD (`sniff.rs`). ⚠️ box cible **codée en dur** (`BOX_SSID` / `CANAL_DEFAUT`) — à paramétrer |
| **Evil twin + portail captif** | ⚠️ | SoftAP + DHCP annonçant notre IP comme DNS + **DNS captif** (`captive_dns.rs`) + page de login capturant `email`/`password` (`eviltwin.rs`) |
| **Portails façon zphisher** | ⚠️ | Templates HTML servis depuis `/sdcard/portals/<site>/index.html`, POST `/login` capturé (pas de PHP côté ESP32) — `portals.rs` |
| Consultation des creds capturés | ⚠️ | Écran « Creds captures » |

## Limitations

- **Cible sniff codée en dur** : `BOX_SSID`/`CANAL_DEFAUT` hérités du code de démo.
- **Mono-tâche** : la capture/l'AP bloquent l'UI jusqu'au retour (bouton LEFT).
- **2.4 GHz** seulement ; non validé en démo de bout en bout.

## Cadre légal

Deauth et AP rogue sont **techniquement légaux en laboratoire fermé** sur du
matériel de l'équipe, mais **strictement interdits** hors de ce cadre
(Art. 323-1 et suivants du Code Pénal). Aucune capture sur réseau tiers.
