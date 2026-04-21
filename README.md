<div align="center">

# 🦎 Axolotl Zero

**Plateforme embarquée de cybersécurité offensive — conçue from scratch**

*Inspirée du Flipper Zero, développée en Rust sur ESP32-S3.*
*Projet annuel ESGI Cybersécurité 2025–2026.*

[![Rust](https://img.shields.io/badge/rust-1.82+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![ESP32-S3](https://img.shields.io/badge/MCU-ESP32--S3-red?logo=espressif&logoColor=white)](https://www.espressif.com/en/products/socs/esp32-s3)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.5.3-blue)](https://github.com/espressif/esp-idf)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![Status](https://img.shields.io/badge/status-WIP-yellow)]()

[Features](#-features) • [Hardware](#-hardware) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Roadmap](#-roadmap)

</div>

---

## 🎯 Pourquoi ?

Les outils de red team comme le Flipper Zero sont des boîtes noires. **Axolotl Zero** est notre réponse pédagogique : un clone entièrement transparent, construit à la main, dont chaque ligne de code et chaque piste du PCB sont documentées et compréhensibles.

> *« Comprendre un outil offensif, c'est déjà comprendre comment s'en défendre. »*

Ce projet est réalisé dans un **cadre strictement pédagogique** — laboratoire ESGI autorisé, matériel appartenant à l'équipe. Voir la [section Éthique](#-éthique--cadre-légal).

---

## ⚡ Features

| Module | Puce | Fréquence | Capacités principales |
|:------:|:----:|:---------:|:----------------------|
| 🏷️ **NFC / RFID** | PN532 | 13.56 MHz | Lecture UID, dump MIFARE Classic, clonage magic card |
| 📶 **Wi-Fi** | ESP32-S3 natif | 2.4 GHz | Scan réseaux, deauth, evil twin AP |
| ⌨️ **BadUSB** | ESP32-S3 USB OTG | USB 2.0 | HID clavier, payloads DuckyScript |
| 📡 **Sub-GHz** | CC1101 | 315 / 433 / 868 MHz | Capture, analyse, replay télécommandes |

Chaque module est démontré en laboratoire avec un scénario d'attaque documenté **et** sa contre-mesure associée.

---

## 🔧 Hardware

<div align="center">

```
        ┌──────────────────────────────────────────┐
        │              AXOLOTL ZERO                │
        │                                          │
        │   ┌────────────┐      ┌─────────────┐    │
        │   │  ST7789    │      │  Joystick   │    │
        │   │  240×240   │      │  5-way      │    │
        │   └─────┬──────┘      └──────┬──────┘    │
        │         │                    │           │
        │         └──────┬─────────────┘           │
        │                │                         │
        │        ┌───────┴────────┐                │
        │        │   ESP32-S3     │                │
        │        │  (Xtensa LX7)  │                │
        │        └───────┬────────┘                │
        │                │                         │
        │    ┌───────┬───┴───┬──────┬────────┐     │
        │    │       │       │      │        │     │
        │  PN532   CC1101   SD   USB-C   Battery   │
        │  (I²C)  (SPI)   (SPI)  (OTG)   (LiPo)    │
        │                                          │
        └──────────────────────────────────────────┘
```

</div>

### Spécifications

| Composant | Référence | Rôle |
|:---------|:----------|:-----|
| **MCU** | ESP32-S3 (Xtensa LX7 dual-core @ 240 MHz) | Cœur applicatif, Wi-Fi, USB natif |
| **Écran** | TFT ST7789 1.54" 240×240 | Interface utilisateur |
| **NFC** | PN532 + antenne 13.56 MHz | Lecture/écriture tags ISO 14443 |
| **Sub-GHz** | CC1101 + antenne 433 MHz | TX/RX ASK/OOK/FSK |
| **Stockage** | Slot microSD (SPI, jusqu'à 32 GB) | Logs, dumps NFC, payloads |
| **Navigation** | Joystick 5-way tactile | Up/Down/Left/Right/Center |
| **Chargeur** | TP4056 (USB-C, CC/CV, 1A) | Charge LiPo |
| **Boost** | MT3608 (3.7V → 5V) | Alimentation sur batterie |
| **Batterie** | LiPo 1S 3.7V 1000 mAh | ~3-5h d'autonomie |
| **Boîtier** | Impression 3D (PLA) — en cours de design | Voir `docs/hardware/` |

📐 **Schémas & pinout complets** → [`docs/architecture.md`](./docs/architecture.md)

### État physique actuel

> 🔬 Le prototype est actuellement **sur breadboard**. La transition vers un boîtier
> imprimé 3D est planifiée en Phase 3 (intégration finale).

```
Phase actuelle ──▶ Breadboard + jumper wires (dev & debug)
Phase suivante ──▶ Boîtier imprimé 3D avec modules fixés (soutenance)
```

---

## 🚀 Quick Start

### Prérequis

- **Rust** ≥ 1.82 avec toolchain Xtensa (`espup`)
- **espflash** pour flasher via USB
- Une Axolotl Zero assemblée (ou un dev kit ESP32-S3 équivalent)

### Installation de la toolchain

```bash
# Toolchain Rust pour Xtensa
cargo install espup
espup install
source ~/export-esp.sh   # ou .bat sous Windows

# Outils de flash
cargo install cargo-espflash espflash
```

### Build & Flash

```bash
# Cloner
git clone https://github.com/0xMrR0bboy/axolotl-zero.git
cd axolotl-zero/axolotl-fw

# Vérifier que la device est détectée
ls /dev/ttyACM*      # Linux/macOS
# ou Device Manager sur Windows

# Build + flash + monitor série
cargo espflash flash --monitor
```

### Premier boot

Au démarrage, le device affiche un splash avec le logo Axolotl, puis le menu principal. Utilisez le joystick pour naviguer :
- **UP / DOWN** : parcourir le menu
- **CENTER** : sélectionner
- **LEFT** : retour

---

## 📚 Documentation

| Document | Description |
|:---------|:------------|
| [📋 Cahier des charges](./docs/cahier-des-charges.md) | Spécification complète du projet (CDC v1.1) |
| [🏗️ Architecture](./docs/architecture.md) | Architecture hardware + software, pinout, bus |
| [🤖 CLAUDE.md](./CLAUDE.md) | Contexte projet pour Claude Code |
| [🏷️ Module NFC](./docs/features/nfc-rfid.md) | Spec détaillée NFC/RFID |
| [📶 Module Wi-Fi](./docs/features/wifi.md) | Spec détaillée Wi-Fi |
| [⌨️ Module BadUSB](./docs/features/bad-usb.md) | Spec détaillée BadUSB |
| [📡 Module Sub-GHz](./docs/features/sub-ghz.md) | Spec détaillée Sub-GHz |
| [🔌 Hardware](./docs/hardware/) | Schémas, BOM, pinout, fichiers 3D |

---

## 🗺️ Roadmap

### ✅ Phase 1 — Fondations *(T0 → M3)*
- [x] Choix composants et sourcing
- [x] Schéma hardware
- [x] PCB routé
- [x] Firmware : boot, splash, menu
- [x] Driver display ST7789
- [x] Driver carte SD (FAT)
- [x] Driver PN532 (I²C) — lecture UID

### 🚧 Phase 2 — Modules offensifs *(M3 → M7)*
- [ ] **NFC** : auth MIFARE, dump dictionnaire, clonage magic card
- [ ] **Wi-Fi** : scan, deauth, evil twin
- [ ] **BadUSB** : HID clavier + parser DuckyScript
- [ ] **Sub-GHz** : driver CC1101, capture/replay 433 MHz

### 🎯 Phase 3 — Finition *(M7 → M10)*
- [ ] Intégration boîtier final
- [ ] Logs horodatés sur SD
- [ ] Documentation démonstrations
- [ ] Rapport technique + slides soutenance

---

## 🏛️ Architecture logicielle

```
┌──────────────────────────────────────────────┐
│               APPLICATION                    │
│   ┌──────┐  ┌──────┐  ┌──────┐  ┌────────┐   │
│   │ NFC  │  │ WiFi │  │BadUSB│  │Sub-GHz │   │
│   └──────┘  └──────┘  └──────┘  └────────┘   │
├──────────────────────────────────────────────┤
│                    UI                        │
│         Menu • Screens • Theme               │
├──────────────────────────────────────────────┤
│                  DRIVERS                     │
│   Buttons • Display • PN532 • CC1101 • SD    │
├──────────────────────────────────────────────┤
│         esp-idf-svc  /  esp-idf-hal          │
├──────────────────────────────────────────────┤
│          ESP-IDF v5.5.3 (C/HAL)              │
├──────────────────────────────────────────────┤
│       ESP32-S3  (Xtensa LX7, FreeRTOS)       │
└──────────────────────────────────────────────┘
```

Le firmware est écrit **100% en Rust** sur les bindings `esp-idf-svc`/`esp-idf-hal`. Les drivers matériels (PN532, CC1101) sont **implémentés from scratch** à partir des datasheets, par choix pédagogique — pas de crate tierce opaque.

---

## 🎓 Différenciation vs Flipper Zero

| Aspect | Flipper Zero | **Axolotl Zero** |
|:-------|:-------------|:-----------------|
| MCU | STM32WB55 (Cortex-M4 64 MHz) | **ESP32-S3 (LX7 dual-core 240 MHz)** |
| Wi-Fi natif | ❌ (module externe) | ✅ **intégré** |
| USB natif | ❌ (via bit-bang) | ✅ **OTG matériel** |
| Sub-GHz | ✅ (CC1101) | ✅ (CC1101) |
| NFC chip | ST25R3916 (avancé) | PN532 (pédagogique) |
| Langage firmware | C | **Rust** |
| Ouverture | Commercial, closed HW | **100% open source** |

> Axolotl Zero n'ambitionne pas de remplacer un Flipper Zero commercial, mais de **prouver** qu'un tel outil est compréhensible, reproductible, et qu'on peut le construire à deux étudiants en un an.

---

## ⚖️ Éthique & Cadre Légal

> ⚠️ **IMPORTANT** : Axolotl Zero est un outil de démonstration **exclusivement pédagogique**.

- ✅ Toutes les démos se font en **laboratoire ESGI** sur du matériel appartenant à l'équipe projet ou explicitement autorisé
- ✅ Respect du **Code Pénal français** (Art. 323-1 et suivants)
- ✅ Respect des **bandes de fréquences** autorisées en France/UE (ERP, duty cycle)
- ❌ **Aucune utilisation** sur systèmes tiers sans autorisation écrite
- ❌ **Aucune distribution** commerciale ni revente

Chaque démonstration est **documentée** avec son périmètre et sa validation préalable par l'encadrant ESGI. Les auteurs déclinent toute responsabilité en cas d'usage contraire au cadre défini.

---

## 👥 Équipe

<div align="center">

| [Ilyes MAJERI](https://github.com/0xMrR0bboy) | [Mathis NGO](https://github.com/0xmatxsu) |
|:---:|:---:|
| Hardware & Firmware | Firmware & Drivers |

*Étudiants en 4ème année Cybersécurité à l'ESGI Paris.*

</div>

---

## 📜 License

Ce projet est distribué sous licence **MIT** — voir [LICENSE](./LICENSE).

Les schémas hardware et fichiers 3D sont sous **CC-BY-SA 4.0**.

---

<div align="center">

**Made with 🦎 & ☕ at ESGI Paris · 2025–2026**

*Si ce projet vous intéresse, laissez une ⭐ — ça nous encourage !*

</div>