# Sub-GHz — CC1101 (315 / 433 / 868 MHz)

> ⚠️ **Différé — retiré de la branche d'intégration `feature/unify`.**
> Le driver CC1101 (`subghz.rs` : OOK/Princeton/RSSI, scan + TX + replay `.sub`)
> avait été écrit et **câblé** dans `main.rs`, puis **retiré** (commit `c709f9f`).
> Il n'est donc **pas** embarqué dans le firmware de cette branche (menu = 4
> entrées, sans Sub-GHz). Le CC1101 reste dans le **design matériel cible**
> (cf. `ARCHITECTURE.md` : BOM, budget courant, bus SPI).

## Où retrouver le code

Le driver est récupérable dans l'historique git :

- `c9ee7be` — « câble le driver CC1101 dans main.rs (scan RSSI + TX Princeton) »
- `f74001d` — « charge et rejoue les .sub depuis la SD (émission FIFO) »

```bash
git show c9ee7be:axolotl-fw/src/subghz.rs > /tmp/subghz.rs   # inspection
```

## À régler avant de le réactiver

1. **Collision GPIO 14** : le CC1101 CS *théorique* est sur GPIO 14, mais cette
   pin sert désormais au **bouton MID** (GPIO 21 d'origine étant inutilisable).
   Il faut réaffecter le CC1101 CS sur une autre pin libre. Voir la note pinout
   dans `ARCHITECTURE.md` / `ARCHITECTURE.md`.
2. **GDO0 non connecté** limitait la capture (repli sur polling RSSI).
3. Réintroduire `mod subghz;` dans `main.rs` et l'entrée de menu associée.

## Cadre légal (bandes ISM France / UE)

| Bande | P max (ERP) | Duty cycle |
|:-----:|:-----------:|:----------:|
| 433.050–434.790 MHz | 10 mW | 10 % |
| 868.000–868.600 MHz | 25 mW | 1 % |
| 915 MHz | ❌ interdit en UE | — |

Capture/replay uniquement sur télécommandes **de l'équipe**, en laboratoire.
