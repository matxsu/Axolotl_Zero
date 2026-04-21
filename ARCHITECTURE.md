# Architecture technique — Axolotl Zero

> Document d'architecture hardware et software de la plateforme Axolotl Zero.
> Version 1.0 — Avril 2026

---

## Table des matières

1. [Vue d'ensemble système](#1-vue-densemble-système)
2. [Architecture matérielle](#2-architecture-matérielle)
3. [Pinout ESP32-S3](#3-pinout-esp32-s3)
4. [Bus de communication](#4-bus-de-communication)
5. [Architecture logicielle](#5-architecture-logicielle)
6. [Machine à états UI](#6-machine-à-états-ui)
7. [Format de fichiers](#7-format-de-fichiers)
8. [Décisions techniques](#8-décisions-techniques)
9. [Contraintes et limitations](#9-contraintes-et-limitations)

---

## 1. Vue d'ensemble système

Axolotl Zero est un système embarqué autonome construit autour d'un ESP32-S3 comme MCU central, intégrant quatre modules offensifs et une interface utilisateur locale.

### Diagramme de haut niveau

```
                   ┌───────────────────────────────────┐
                   │         INTERACTION UTILISATEUR   │
                   │  Joystick 5-way   +   TFT 240×240 │
                   └──────────────┬────────────────────┘
                                  │
                  ┌───────────────▼───────────────┐
                  │          ESP32-S3             │
                  │    Xtensa LX7 dual-core       │
                  │    240 MHz · 512 KB SRAM      │
                  │    8 MB PSRAM · 16 MB flash   │
                  └──┬────────┬────────┬──────┬───┘
                     │        │        │      │
                I²C ▼   SPI ▼    SPI ▼      USB ▼
                 ┌─────┐  ┌──────┐  ┌──────┐ ┌─────────┐
                 │PN532│  │CC1101│  │SD card│ │USB-C HID│
                 │NFC  │  │Sub-GHz│ │FAT32 │ │BadUSB   │
                 │13.56│  │315/433│ │      │ │         │
                 │ MHz │  │868MHz │ │      │ │         │
                 └─────┘  └──────┘  └──────┘ └─────────┘

                  [Wi-Fi 2.4 GHz intégré dans l'ESP32-S3]
                  [Bluetooth LE 5.0 intégré, hors scope]
```

### Entrées / sorties

| Direction | Interface | Usage |
|:---------:|:----------|:------|
| **Entrée** | Joystick 5-way | Navigation UI |
| **Entrée** | PN532 | Tags NFC/RFID |
| **Entrée** | CC1101 RX | Signaux Sub-GHz |
| **Entrée** | SD card | Payloads, dumps sauvegardés |
| **Entrée/Sortie** | USB-C | HID (BadUSB) + alimentation + flash firmware |
| **Sortie** | TFT ST7789 | Feedback visuel |
| **Sortie** | CC1101 TX | Replay Sub-GHz |
| **Sortie** | SD card | Logs, dumps NFC |
| **Sortie** | Wi-Fi ESP32-S3 | Deauth frames, evil twin AP |

---

## 2. Architecture matérielle

### Bloc-diagramme électronique

```
                       ┌───────────────┐
                   VBUS│    USB-C      │D+/D-
                       │  (charge +    │
                       │   data/flash) │
                       └───┬───────┬───┘
                           │       │
             ┌─────────────▼──┐    │
             │    TP4056      │    │
             │  LiPo Charger  │    │
             │ CC/CV → 4.2V   │    │
             │  Imax = 1A     │    │
             └──┬─────────┬───┘    │
         CHRG ──┘ (LED)   │        │
         STDBY ──  (LED)  │        │
                          ▼        │
                     ┌─────────┐   │
                     │  LiPo   │   │
                     │  1S     │   │
                     │ 3.7V    │   │
                     │ 1000mAh │   │
                     └────┬────┘   │
                          │        │
                   ┌──────▼──────┐ │
                   │   MT3608    │ │
                   │ Boost Conv. │ │
                   │ 3.7V → 5V   │ │
                   │  Imax 2A   │ │
                   └──────┬──────┘ │
                          │        │
                     ┌────▼────┐   │
                     │  LDO    │   │       USB OTG
                     │  3.3V   │   │    (BadUSB HID)
                     └────┬────┘   │         │
                          │        │         │
         ┌────────────────┴────────▼─────────▼─────┐
         │                                         │
         │               ESP32-S3                  │
         │            Xtensa LX7 × 2               │
         │                                         │
         │  GPIO3 ──── I²C SDA  ──────┐            │
         │  GPIO4 ──── I²C SCL  ──────┤            │
         │                            │            │
         │  GPIO6  ─── SPI CS (SD)  ──┤            │
         │  GPIO8  ─── SPI CS (LCD) ──┤            │
         │  GPIO9  ─── LCD D/C  ──────┤            │
         │  GPIO10 ─── LCD RST  ──────┤            │
         │  GPIO11 ─── SPI MOSI ──────┤            │
         │  GPIO12 ─── SPI SCK  ──────┤            │
         │  GPIO13 ─── SPI MISO ──────┤            │
         │  GPIO14 ─── SPI CS (CC1101)┤            │
         │  GPIO38 ─── CC1101 GDO0 ───┤            │
         │  GPIO39 ─── CC1101 GDO2 ───┤            │
         │  GPIO46 ─── LCD BLK  ──────┤            │
         │                            │            │
         │  GPIO15..18,21 Joystick    ┤            │
         │                                         │
         └──────────┬──────────────────────────────┘
                    │
         ┌──────────┼──────────┬───────────┐
         │          │          │           │
    ┌────▼──┐  ┌────▼────┐  ┌──▼────┐  ┌───▼───┐
    │PN532  │  │ CC1101  │  │TFT    │  │SD     │
    │NFC    │  │Sub-GHz  │  │ST7789 │  │card   │
    │13.56  │  │315/433/ │  │240×240│  │SPI    │
    │ MHz   │  │868 MHz  │  │       │  │       │
    └───┬───┘  └────┬────┘  └───────┘  └───────┘
        │           │
     ┌──▼──┐     ┌──▼──┐
     │ANT  │     │ANT  │
     │13.56│     │ 433 │
     │ MHz │     │ MHz │
     └─────┘     └─────┘
```

### Chaîne d'alimentation

Le système d'alimentation assure deux fonctions : charger la batterie LiPo et fournir
un 3.3V stable à tous les composants. Deux modes de fonctionnement sont supportés.

**Mode alimenté USB-C** : USB 5V → TP4056 charge la LiPo (CC/CV, 4.2V, courant
programmable via Rprog) → sortie OUT alimente le MT3608 (bypass à ~4.2V) → LDO 3.3V.
L'ESP32-S3 utilise aussi l'USB pour le flash firmware et le debug série (GPIO43/44 UART0).

**Mode autonome batterie** : LiPo 3.7V nominal (3.0–4.2V) → MT3608 boost à 5V → LDO
3.3V. Ce chemin fournit ~2A max grâce au MT3608 step-up.

```
    Mode USB-C :   USB 5V ──▶ TP4056 ──▶ LiPo ──▶ MT3608 ──▶ LDO 3.3V ──▶ ESP32-S3
    Mode batterie :                        LiPo ──▶ MT3608 ──▶ LDO 3.3V ──▶ ESP32-S3
```

**Indicateurs visuels (TP4056)** :
- LED rouge (CHRG) : charge en cours
- LED verte/bleue (STDBY) : charge terminée
- Les deux éteintes : pas d'alimentation USB ou batterie absente

**Budget courant estimé** (worst case, tous modules actifs) :

| Consommateur | Courant typ. | Notes |
|:-------------|:-------------|:------|
| ESP32-S3 (Wi-Fi TX) | ~240 mA | Pic en mode 802.11 transmit |
| TFT ST7789 + backlight | ~40 mA | |
| PN532 (scan NFC) | ~100 mA | Pic lors de l'émission RF |
| CC1101 (TX +12 dBm) | ~34 mA | D'après la datasheet |
| Lecteur SD (écriture) | ~100 mA | Pic SPI burst |
| **Total worst case** | **~514 mA** | |

Avec une LiPo 1000 mAh et ~514 mA worst case, l'autonomie théorique est d'environ
**1h50 en utilisation intensive continue**. En usage mixte (scan NFC ponctuel, écran actif,
Wi-Fi idle), on peut espérer **3–5h**.

> ⚠️ Le Flipper Zero obtient ses 28 jours grâce à un power management bien plus
> sophistiqué (BQ25896 PMIC + BQ27220 fuel gauge + deep sleep agressif). Sur
> Axolotl Zero v1, le power management est minimal — pas de deep sleep, pas de
> fuel gauge — c'est un choix assumé.

### Comparaison Flipper Zero — Alimentation

| | Flipper Zero | Axolotl Zero |
|:--|:-------------|:-------------|
| **Chargeur** | BQ25896 (switching, 3A) | TP4056 (linéaire, 1A) |
| **Fuel gauge** | BQ27220 (I²C, SoC%) | ❌ Pas de jauge |
| **Batterie** | LiPo 2100 mAh | LiPo 1000 mAh |
| **Régulateur** | LM3281 (DC-DC buck) | MT3608 (boost) + LDO |
| **Deep sleep** | ✅ (~40 µA) | ❌ Non implémenté v1 |
| **Autonomie** | ~28 jours (usage léger) | ~3–5h (estimation) |
| **Indicateurs** | Icône batterie sur écran | LEDs TP4056 uniquement |

### Bill of Materials (principal)

| Réf | Composant | Qté | Prix ~  | Note |
|:---:|:----------|:---:|:-------:|:-----|
| U1 | ESP32-S3-WROOM-1 (N16R8) | 1 | 3€ | 16 MB flash, 8 MB PSRAM |
| U2 | PN532 module breakout | 1 | 5€ | Antenne PCB intégrée |
| U3 | CC1101 module | 1 | 3€ | Antenne SMA externe 433 MHz |
| U4 | TFT ST7789 1.54" 240×240 | 1 | 4€ | SPI 4-wire |
| U5 | Lecteur microSD SPI | 1 | 1€ | 5 broches |
| U6 | Module TP4056 (USB-C) | 1 | 1€ | Chargeur LiPo CC/CV 1A |
| U7 | Module MT3608 | 1 | 1€ | Boost 3.7V → 5V |
| U8 | LDO 3.3V AMS1117 | 1 | 0.5€ | I_out ≥ 500 mA |
| SW1–5 | Joystick tactile 5-way | 1 | 2€ | Ou 5 boutons séparés |
| J1 | Connecteur USB-C (sur TP4056) | 1 | — | Intégré au module |
| BAT1 | LiPo 1S 3.7V 1000 mAh | 1 | 5€ | Connecteur JST-PH 2.0 |
| ANT1 | Antenne SMA 433 MHz | 1 | 2€ | Pour CC1101 |
| — | Breadboard 830 pts | 1 | — | Phase prototype |
| — | Jumper wires | ~40 | — | Phase prototype |
| **Total** | | | **~27€** | Hors breadboard/jumpers |

📎 **BOM complète** → [`hardware/bom.md`](./hardware/bom.md) *(à créer)*

### État physique actuel et trajectoire

**Phase actuelle : breadboard**

Tous les composants sont câblés sur une breadboard 830 points avec des jumper wires.
C'est suffisant pour le développement et le debug, mais pose des problèmes de
fiabilité (contacts intermittents, longueur de pistes, interférences) et rend le device
non-portable.

**Phase cible : boîtier imprimé 3D**

Objectif : transférer le montage breadboard dans un boîtier rigide imprimé en PLA/PETG,
avec les modules fixés mécaniquement. Les éléments à prévoir :

```
┌─────────────────────────────────────────────┐
│   Boîtier imprimé 3D (PLA)                 │
│                                             │
│   ┌──────────────────┐  ┌──────────────┐    │
│   │   Écran TFT      │  │  Joystick    │    │
│   │   (ouverture)    │  │  (perçage)   │    │
│   └──────────────────┘  └──────────────┘    │
│                                             │
│   ┌─────────────────────────────────────┐   │
│   │  PCB principal (ESP32-S3 dev kit)   │   │
│   └─────────────────────────────────────┘   │
│                                             │
│   ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐  │
│   │PN532 │ │CC1101│ │SD    │ │TP4056    │  │
│   └──────┘ └──────┘ └──────┘ │+MT3608   │  │
│                               │+LiPo    │  │
│                               └──────────┘  │
│   ┌───────────────────────────────────────┐ │
│   │ USB-C (ouverture latérale)            │ │
│   └───────────────────────────────────────┘ │
│   ┌───────────────────────────────────────┐ │
│   │ Antenne SMA 433 MHz (ouverture)       │ │
│   └───────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
```

Dimensions cibles estimées : **120 × 70 × 35 mm** (à affiner après modélisation).
Pour référence, le Flipper Zero fait 100 × 40 × 25 mm — notre device sera plus épais
car il empile des modules breakout au lieu d'un PCB custom.

Livrables boîtier :
- Fichiers STL / STEP pour impression
- Fichiers source FreeCAD ou Fusion360
- Documentation du montage (vis, entretoises, passage câbles)

---

## 3. Pinout ESP32-S3

### Table d'affectation

| GPIO | Rôle | Bus / Périph | Direction | Notes |
|:----:|:-----|:-------------|:---------:|:------|
| 3 | I²C SDA | I²C0 | Bidi | PN532 @ 0x24 |
| 4 | I²C SCL | I²C0 | Bidi | PN532 @ 0x24 |
| 6 | SD CS | SPI2 | Out | |
| 8 | LCD CS | SPI2 | Out | |
| 9 | LCD D/C | GPIO | Out | Data/Command |
| 10 | LCD RST | GPIO | Out | Actif bas |
| 11 | SPI MOSI | SPI2 | Out | **Partagé LCD+SD+CC1101** |
| 12 | SPI SCK | SPI2 | Out | **Partagé LCD+SD+CC1101** |
| 13 | SPI MISO | SPI2 | In | Partagé SD+CC1101 (LCD WO) |
| 14 | CC1101 CS | SPI2 | Out | |
| 15 | Joystick UP | GPIO | In PU | Pull-up interne |
| 16 | Joystick DOWN | GPIO | In PU | |
| 17 | Joystick LEFT | GPIO | In PU | |
| 18 | Joystick RIGHT | GPIO | In PU | |
| 19 | USB D- | USB OTG | Bidi | BadUSB HID |
| 20 | USB D+ | USB OTG | Bidi | BadUSB HID |
| 21 | Joystick CENTER | GPIO | In PU | |
| 38 | CC1101 GDO0 | GPIO IRQ | In | TX/RX event |
| 39 | CC1101 GDO2 | GPIO IRQ | In | FIFO threshold |
| 46 | LCD BLK | GPIO | Out | Backlight |

### Pins réservées / inutilisables

| GPIO | Raison |
|:----:|:-------|
| 0 | Boot select (actif à LOW au reset) |
| 45, 46 | Strapping pins (VDD_SPI, JTAG sel) — 46 utilisé pour LCD BLK, OK si HIGH par défaut |
| 26–32 | Connectées à la flash SPI interne (N16R8) |
| 33–37 | Connectées à la PSRAM octale interne |
| 43, 44 | UART0 (console série, debug) |

> ⚠️ L'ESP32-S3 WROOM-1 **N16R8** utilise les GPIO 26–37 pour la mémoire interne.
> Elles **ne sont pas utilisables** comme GPIO externes. Toujours vérifier la
> variante de puce avant de designer.

---

## 4. Bus de communication

### SPI2 — bus partagé

Un **seul** contrôleur SPI matériel est utilisé pour trois périphériques, grâce à des CS distincts :

```
    SPI2 (SpiDriver)
    ├── SpiDeviceDriver(CS=GPIO8)  → LCD ST7789   @ 40 MHz, MODE_3
    ├── SpiDeviceDriver(CS=GPIO6)  → SD card      @ 20 MHz, MODE_0
    └── SpiDeviceDriver(CS=GPIO14) → CC1101       @ 5 MHz,  MODE_0
```

Chaque `SpiDeviceDriver` gère automatiquement son CS et sa configuration. Le HAL ESP-IDF sérialise les accès concurrents.

> 🚫 **Anti-pattern à éviter** : créer deux `SpiDriver` distincts sur les mêmes
> pins physiques. Résultat : conflit matériel, un seul fonctionne, l'autre
> échoue silencieusement ou corrompt les trames.

### I²C0 — PN532

```
    I²C0 @ 100 kHz
    └── 0x24  → PN532 (7-bit address)
```

L'adresse 7-bit `0x24` correspond au `0x48` en 8-bit avec R/W=0. Le PN532 supporte jusqu'à 400 kHz (Fast mode) mais 100 kHz offre une meilleure marge d'erreur en présence de longues pistes PCB.

### USB OTG — BadUSB

```
    USB 2.0 Full-Speed (12 Mbps)
    ├── Device mode : HID Keyboard (vendor 0x303A / product TBD)
    └── Controlled by TinyUSB via esp-idf-svc
```

L'ESP32-S3 supporte nativement USB OTG. L'énumération se fait au moment où le firmware active le mode BadUSB depuis le menu — pas au boot, pour éviter d'énumérer un clavier parasite à chaque alimentation.

### Wi-Fi — radio intégrée

```
    802.11 b/g/n @ 2.4 GHz
    ├── Mode STA : scan, connexion (rarement utilisé)
    ├── Mode AP  : evil twin, rogue AP
    └── Mode PROMISCUOUS : capture, injection deauth
```

---

## 5. Architecture logicielle

### Arborescence du firmware

```
axolotl-fw/src/
├── main.rs              Boot + boucle événementielle (< 150 lignes visé)
├── logo.rs              Bitmap 120×60 du splash (généré)
├── ui/
│   ├── mod.rs
│   ├── menu.rs          Menu principal (MenuItem, render)
│   ├── theme.rs         Couleurs, polices, tailles
│   └── screens/
│       ├── mod.rs
│       ├── nfc.rs       Écran NFC : scan, dump, résultats
│       ├── wifi.rs      Écran Wi-Fi : scan, deauth, AP
│       ├── bad_usb.rs   Écran BadUSB : liste payloads, exec
│       ├── sub_ghz.rs   Écran Sub-GHz : capture, replay
│       └── storage.rs   Écran stockage : liste fichiers, stats
├── drivers/
│   ├── mod.rs
│   ├── buttons.rs       Struct Buttons {up, down, left, right, center}
│   ├── display.rs       Wrapper ST7789, helpers draw
│   ├── pn532.rs         Driver I²C PN532 (from scratch)
│   ├── cc1101.rs        Driver SPI CC1101 (from scratch)
│   └── sdcard.rs        Wrapper FAT32
├── nfc/
│   ├── mod.rs           NfcTarget, high-level API
│   ├── mifare.rs        Authenticate, read_block, write_block
│   ├── attacks.rs       Dictionary attack, nested (stretch)
│   ├── keys.rs          Default key dictionary
│   └── dump.rs          Format .mfd compatible Flipper/Proxmark
├── wifi/
│   ├── mod.rs
│   ├── scan.rs          Liste réseaux + métadonnées
│   ├── deauth.rs        Injection de trames 802.11
│   └── evil_twin.rs     AP + portail captif
├── bad_usb/
│   ├── mod.rs
│   ├── hid.rs           Driver HID keyboard
│   ├── ducky.rs         Parser DuckyScript
│   └── runner.rs        Exécution de payload
└── sub_ghz/
    ├── mod.rs
    ├── config.rs        Registres CC1101 pour différents protocoles
    ├── capture.rs       RX + décodage ASK/OOK
    └── replay.rs        TX d'une trame capturée
```

### Couches logicielles

```
┌─────────────────────────────────────────────────┐
│                 APPLICATION                     │
│  (nfc::attacks, wifi::deauth, bad_usb::runner)  │
│            Business logic, attaques             │
├─────────────────────────────────────────────────┤
│                      UI                         │
│        (ui::menu, ui::screens::*)               │
│   Rendu, gestion boutons, navigation écrans     │
├─────────────────────────────────────────────────┤
│                   DRIVERS                       │
│  (drivers::pn532, drivers::cc1101, buttons...)  │
│       Abstraction matérielle custom             │
├─────────────────────────────────────────────────┤
│         esp-idf-svc  /  esp-idf-hal             │
│       Bindings Rust vers ESP-IDF                │
├─────────────────────────────────────────────────┤
│             ESP-IDF v5.5.3                      │
│     FreeRTOS, HAL C, drivers Espressif          │
├─────────────────────────────────────────────────┤
│                  HARDWARE                       │
│           ESP32-S3 + périphériques              │
└─────────────────────────────────────────────────┘
```

### Conventions inter-modules

- Les drivers retournent `anyhow::Result<T>`, pas d'erreurs custom
- Les modules d'attaque prennent un `&mut Driver` (pas de `Arc`/`Mutex` — mono-tâche)
- L'UI ne connaît pas les drivers directement — elle passe par les modules haut niveau
- Les constantes matérielles (pins, fréquences) sont **uniquement** dans `main.rs` et passées en paramètre aux constructeurs

---

## 6. Machine à états UI

### État global

```
     ┌─────────┐
     │  BOOT   │
     └────┬────┘
          │ (1s splash)
          ▼
     ┌─────────┐
     │  MENU   │◀──────────────────┐
     └────┬────┘                   │
          │ CENTER                 │ LEFT (back)
          │                        │
          ▼                        │
    ┌──────────────────────┐       │
    │  SCREEN (par module) │───────┘
    │  - NFC               │
    │  - Wi-Fi             │
    │  - BadUSB            │
    │  - Sub-GHz           │
    │  - Storage           │
    └──────────────────────┘
```

### État du screen NFC (détail)

```
     ┌────────────┐
     │   IDLE     │  "Approchez une carte"
     └──────┬─────┘
            │ carte détectée (PN532.read_uid)
            ▼
     ┌────────────┐
     │ UID SHOWN  │  affiche UID
     └──────┬─────┘
        CENTER pour dump
            │
            ▼
     ┌────────────┐
     │ DUMPING    │  "Attaque en cours..."
     └──────┬─────┘
            │ terminé
            ▼
     ┌────────────┐
     │ DUMP DONE  │  N secteurs, X clés trouvées
     └──────┬─────┘
        LEFT  │  CENTER = save
              ▼
          [IDLE]
```

Toutes les transitions bloquent sur polling joystick (pas d'interruptions). C'est acceptable en mono-tâche car la boucle événementielle a un cycle de ~20 ms.

---

## 7. Format de fichiers

### Logs sur SD card

Structure `/sdcard/` :

```
/sdcard/
├── NFC/
│   ├── dumps/
│   │   ├── 04AB12CD.mfd        Dump binaire compatible Flipper
│   │   └── 04AB12CD.txt        Version humaine lisible
│   └── session.log             Historique des scans
├── WIFI/
│   ├── scans/
│   │   └── 2026-04-16_1430.csv Réseaux scannés (SSID,BSSID,ch,RSSI,enc)
│   └── captures/
│       └── *.pcap              Captures promiscuous
├── BADUSB/
│   └── payloads/
│       ├── hello_world.ducky
│       └── powershell_demo.ducky
└── SUBGHZ/
    └── captures/
        └── 433_remote_01.sub   Signal capturé (format custom)
```

### Format `.mfd` (MIFARE Dump)

Binaire brut, 1024 octets pour MIFARE Classic 1K :

```
Offset  Size  Contenu
─────────────────────
0x000   16    Bloc 0 (UID + manufacturer)
0x010   16    Bloc 1
0x020   16    Bloc 2
0x030   16    Bloc 3 (trailer secteur 0 : KeyA + access + KeyB)
0x040   16    Bloc 4
...
0x3F0   16    Bloc 63 (trailer secteur 15)
─────────────────────
Total   1024
```

Format **compatible** avec :
- Flipper Zero (`.mfd` natif)
- Proxmark3 (`hf mf rdbl`)
- mfoc, mfcuk, nfc-mfclassic

### Format `.ducky` (DuckyScript)

Texte UTF-8, compatible syntaxe Rubber Ducky v1 :

```
REM Démo BadUSB — ouvre un terminal et affiche un message
DELAY 500
GUI r
DELAY 200
STRING cmd
ENTER
DELAY 500
STRING echo Hello from Axolotl Zero
ENTER
```

---

## 8. Décisions techniques

### 8.1 Rust vs C

Le CDC v1.0 mentionnait C/ESP-IDF comme langage principal et Rust comme optionnel. **La v1.1 officialise Rust comme langage unique** du firmware.

**Raisons** :
- Sécurité mémoire par design (pas de buffer overflow, use-after-free)
- Système de types plus expressif que C, réduit les bugs de drivers
- `cargo` > CMake + idf.py pour la productivité
- Compétence différenciante pour le CV
- `esp-idf-svc` / `esp-idf-hal` sont matures en 2026

**Arbitrage accepté** :
- Temps de compilation plus long (~2-3 min vs ~30s en C)
- Moins d'exemples communautaires (mais suffisant)
- Patchs git `esp-idf-*` parfois nécessaires

### 8.2 ESP32-S3 vs STM32WB55 (Flipper Zero)

| Critère | STM32WB55 (Flipper) | ESP32-S3 (Axolotl) |
|:--------|:--------------------|:-------------------|
| Prix | ~8€ | ~3€ |
| Wi-Fi | ❌ | ✅ natif |
| BLE | ✅ 5.4 | ✅ 5.0 |
| USB OTG | Via bit-bang | Natif matériel |
| Dual-core | Oui (M4+M0) | Oui (LX7 dual) |
| Fréquence | 64 MHz | 240 MHz |
| RAM | 256 KB | 512 KB (+8 MB PSRAM) |
| Consommation | Très basse | Moyenne |
| Écosystème Rust | Moyen | Excellent (esp-rs) |

L'ESP32-S3 est choisi principalement pour le **Wi-Fi natif** (absent sur Flipper sans dev board) et le **support Rust mature**.

### 8.3 PN532 vs ST25R3916 (Flipper Zero)

Le Flipper utilise un ST25R3916 beaucoup plus capable (HID iClass/Picopass, FeliCa, vitesse). Nous utilisons un **PN532** pour :
- Disponibilité (modules breakout ~5€ partout)
- Documentation abondante
- Librairies Rust existantes (référence `pn532` crate, même si nous implémentons from scratch)
- Scope suffisant pour MIFARE Classic (cœur de la démo pédagogique)

**Conséquence** : HID iClass/Picopass/FeliCa hors scope. Documenté.

### 8.4 CC1101 (Sub-GHz)

Même puce que le Flipper Zero. Choix motivé par :
- **Standard de facto** du milieu Sub-GHz hobbyiste
- Documentation exhaustive (AN dn470 de TI, wikis Flipper)
- Modulations ASK/OOK/FSK/GFSK/MSK couvrent 95% des usages civils
- ~3€ par module

### 8.5 Bus SPI unique

Alternative évaluée : un SPI par périphérique (SPI2 pour LCD, SPI3 pour SD+CC1101). **Rejeté** car :
- L'ESP32-S3 n'a que 2 SPI "généraux" (SPI2/SPI3), donc pas de marge
- Le partage via `SpiDeviceDriver` est le pattern officiel recommandé par Espressif
- Les périphériques ont des fréquences compatibles (40/20/5 MHz)
- Le HAL gère le multiplexage temporel correctement

---

## 9. Contraintes et limitations

### Matérielles

- **Wi-Fi 2.4 GHz uniquement** — le 5 GHz n'est pas supporté par l'ESP32-S3
- **Sub-GHz 300–928 MHz uniquement** — hors de cette plage, le CC1101 ne transmet pas
- **NFC 13.56 MHz uniquement** — pas de 125 kHz (pas de RFID badge parking)
- **MIFARE Classic/Ultralight** — DESFire, FeliCa, iClass hors portée PN532
- **Puissance TX Sub-GHz limitée à 10 dBm** — portée ~50 m en champ libre
- **Batterie LiPo optionnelle** — prototype v1 alimenté USB-C principalement

### Légales (France / UE)

| Bande | Puissance max (ERP) | Duty cycle | Notes |
|:-----:|:-------------------:|:----------:|:------|
| 433.050–434.790 MHz | 10 mW | 10 % | Télécommandes, capteurs |
| 868.000–868.600 MHz | 25 mW | 1 % | ISM, LoRa |
| 868.700–869.200 MHz | 25 mW | 0.1 % | |
| 915 MHz | ❌ **Interdit en UE** | — | Bande US/Asie |
| 2.4 GHz Wi-Fi | 100 mW (indoor) | — | ETSI EN 300 328 |

Les attaques de désauthentification et la création d'un AP rogue sont **techniquement légales en laboratoire fermé** sur matériel détenu par l'équipe, mais **strictement interdites** hors de ce cadre (Art. 323-1 et suivants du Code Pénal).

### Logicielles

- **Mono-tâche** — pas de multi-threading Rust. Les opérations longues (dump NFC, capture Sub-GHz) bloquent l'UI. Acceptable pour un outil interactif.
- **Pas de BLE** — la stack Bluetooth de l'ESP32-S3 est disponible mais non intégrée, hors scope v1
- **Pas de suspension / wake-up** — le device reste ON tant qu'il est alimenté. Pas de deep sleep implémenté.

---

## Annexes

- [`hardware/schematics/`](./hardware/schematics/) — Schémas KiCad (PDF export)
- [`hardware/bom.md`](./hardware/bom.md) — Bill of materials complet
- [`features/`](./features/) — Spécifications détaillées par module
- [`cahier-des-charges.md`](./cahier-des-charges.md) — CDC v1.1

---

**Version** : 1.0 · **Auteurs** : Ilyes MAJERI & Mathis NGO · **ESGI** · Avril 2026