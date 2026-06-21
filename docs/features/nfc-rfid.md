# NFC / RFID — 13.56 MHz (PN532)

> État au 21 juin 2026. Module le plus abouti du projet.
> Driver : `axolotl-fw/src/nfc/mod.rs` (PN532 I²C, from scratch) + `attacks.rs`
> (dump dictionnaire). Logique pure & testable : crate `axolotl-core`
> (`card`, `dump`, `layout`, `keys`, `protocol`, `acl`, `crypto1`).

## Matériel

- **PN532** en I²C : SDA=GPIO3, SCL=GPIO4, 100 kHz (baissé à 40 kHz + pull-ups
  internes pour la robustesse sur breadboard).
- Cibles supportées : **MIFARE Classic 1K/4K/Mini** (Crypto1) et **Ultralight/NTAG**.
- ⚠️ Le PN532 en I²C sans résistances pull-up externes est **instable**
  (timeouts au boot, échecs sporadiques). Pull-up 4.7 kΩ externes = correctif HW.

## Fonctionnalités implémentées

| Capacité | État | Notes |
|---|---|---|
| Scan UID + type (SAK/ATQA) | ✅ | `read_uid`, `NfcUid::card_type` |
| Auth MIFARE (KeyA/KeyB) | ✅ | `InDataExchange` / MFAuthent |
| Lecture/écriture bloc | ✅ | `mifare_read_block` / `mifare_write_block` |
| **Dump par dictionnaire** | ✅ | 238 clés ; **cache clés Phase 0** : un badge monoclé passe de ~2 min à ~12 s |
| Sauvegarde `.mfd` + `.txt` | ✅ | clés réinjectées dans les trailers → re-clonable sans la carte source ; scan des 2 racines `/sdcard` + `/spiflash` |
| **Clone carte magic** | ✅ | gen2/CUID (write bloc 0 après auth) + fallback gen1a (backdoor `0x40`) ; **garde-fou** : refuse une cible non-magic (anti-brick) |
| Wipe gen1a | ✅ | efface via backdoor, trailers → transport state |
| Ultralight / NTAG | ✅ | lecture/clone pages |
| **Émulation MIFARE (Crypto1 SW)** | ⚠️ | `tg_init_as_target` + Crypto1 logiciel ESP32. **Non vérifiée sur lecteur réel** — échoue souvent (timing PN532+I²C trop lent). Le clone physique reste la voie fiable. |
| Darkside / Nested / Probe PRNG | ❌ retirées | Le PN532 ne permet pas le contrôle bit-timing requis → **Proxmark3 obligatoire**. Code dans l'historique git. |

## Cartes « magic » (obligatoires pour le clone physique)

Le bloc 0 (UID) d'une **MIFARE Classic standard est verrouillé en silicium** :
aucun firmware ne peut le réécrire. Le clone exige une carte magic :

- **Gen1a** — backdoor `0x40/0x43`, écriture sans auth.
- **Gen2 / CUID** — bloc 0 réinscriptible par WRITE normal après auth (clé d'usine `FFFFFFFFFFFF`).

Le clone détecte automatiquement le type ; toute carte affichant « cible
non-magic » est une carte standard (non clonable). Réf. produit testée : T4U CUID Gen2.

## Flux utilisateur (UI)

```
Menu → NFC/RFID
 ├─ Poser une carte → scan UID/type
 │   └─ MID : dump (dict) → si 64/64 : sauvegarde auto → MID clone / DOWN attaques (Wipe gen1a)
 ├─ RIGHT : dumps sauvés (scan /sdcard + /spiflash)
 │   └─ ouvrir → UP émuler (approche lecteur) · MID cloner (carte magic) · DOWN voir blocs
 ├─ UP : re-clone du dernier dump en RAM
 └─ DOWN : voir les blocs du dernier dump
```

## Cadre légal

Tests **exclusivement** sur badges appartenant à l'équipe, en laboratoire ESGI.
Copier un badge tiers sans autorisation est illégal (Art. 323-1 et s. du Code Pénal).
