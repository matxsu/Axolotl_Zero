# BadUSB — clavier HID (Bluetooth LE)

> État au 4 juillet 2026 (branche `feature/unify`). **Implémenté**, validation
> en démo matérielle à faire. Driver : `axolotl-fw/src/badusb.rs`.
> ⚠️ Contrairement à un « BadUSB » classique, l'injection passe par un **clavier
> HID Bluetooth LE** (`esp32-nimble`), **pas** par l'USB OTG natif.

## Matériel

- **Radio BLE intégrée** à l'ESP32-S3 — aucun composant externe.
- L'hôte cible doit **appairer** le périphérique « Axolotl Keyboard » avant que
  l'injection ne fonctionne (PC, smartphone… toute cible BLE HID).
- L'USB OTG (GPIO19/20) reste réservé au **flash firmware et à la console série**.

## Fonctionnalités implémentées

| Capacité | État | Notes |
|---|---|---|
| Clavier HID BLE | ⚠️ | `esp32-nimble` (NimBLE), advertising « Axolotl Keyboard », touches clavier + média |
| Layout **AZERTY (FR)** | ⚠️ | Table de conversion caractère → keycode HID intégrée |
| Interpréteur DuckyScript | ⚠️ | Sous-ensemble : `REM`, `DELAY`, `DEFAULTDELAY`/`DEFAULT_DELAY`, `STRING`, `STRINGLN`, modificateurs `GUI`/`WIN`/`CTRL`/`SHIFT`/`ALT` (+ combos), touches `ENTER`/`ESC`/`TAB`/flèches |
| Payloads depuis la SD | ⚠️ | Lus dans `/sdcard/payloads/*.txt`, sélection au menu |
| Payloads de démo | ✅ | 5 payloads bénins intégrés (`BUILTIN_PAYLOADS`) : Notepad, calc, ouverture URL, verrouillage session, `ipconfig` |
| Payload test reverse-shell | ⚠️ | Derrière la feature Cargo **opt-in** `lab_payload` (désactivée par défaut) — usage laboratoire uniquement |
| Libération BLE en sortie | ✅ | `BLEDevice::deinit()` au retour menu (évite un clavier fantôme) |

> ℹ️ `BUILTIN_PAYLOADS` est actuellement **défini mais pas branché** dans l'UI
> (l'écran lit les payloads sur SD). C'est le seul consommateur de la feature
> `lab_payload` : à câbler comme liste de secours, ou à retirer avec la feature.

## Limitations

- **BLE, pas USB HID** : nécessite un appairage explicite côté cible.
- Layout **AZERTY** figé (un clavier configuré QWERTY côté hôte tapera mal).
- Non validé en démo : timing d'appairage et fiabilité d'injection à éprouver.

## Cadre légal

Démonstration en **laboratoire ESGI**, sur machine de l'équipe. L'injection de
frappes sur un poste tiers sans autorisation est illégale (Art. 323-1 CP).
