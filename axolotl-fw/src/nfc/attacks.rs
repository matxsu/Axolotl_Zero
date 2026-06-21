//! Attaques MIFARE Classic : dump par dictionnaire de clés.

use axolotl_core::{
    keys::DEFAULT_KEYS,
    layout::ClassicType,
    protocol::{MIFARE_AUTH_A, MIFARE_AUTH_B},
    MifareDump, NfcUid,
};

use super::Pn532;

const RE_SELECT_RETRIES: u8 = 5;

/// Cadence du log de progression pendant le brute-force d'un secteur (1 ligne
/// INFO toutes les N clés essayées). Évite les longs silences trompeurs.
const PROGRESS_EVERY: usize = 32;

/// Clé trouvée pour un secteur pendant le dict attack.
#[derive(Clone, Copy)]
pub struct SectorKey {
    pub sector: u8,
    pub key_ab: u8, // 0 = KeyA, 1 = KeyB
    pub key: [u8; 6],
}

/// Sérialise le dump au format .mfd en RÉINJECTANT les clés trouvées dans les
/// trailers (la carte renvoie KeyA masquée à 00 ; un .mfd standard Proxmark/
/// Flipper contient les vraies clés). Le dump en RAM reste inchangé.
///
/// Ce format permet de re-cloner plus tard depuis le fichier seul, sans
/// re-scanner la carte source ni reconserver les clés à part.
pub fn dump_to_mfd_with_keys(dump: &MifareDump, keys: &[SectorKey]) -> Vec<u8> {
    let mut bytes = dump.to_mfd_bytes();
    let card_type = dump.card_type;
    for k in keys {
        if let Some(trailer) = card_type.sector_trailer(k.sector) {
            let off = trailer as usize * 16;
            if off + 16 <= bytes.len() {
                if k.key_ab == 0 {
                    bytes[off..off + 6].copy_from_slice(&k.key);
                } else {
                    bytes[off + 10..off + 16].copy_from_slice(&k.key);
                }
            }
        }
    }
    bytes
}

/// Reconstruit la liste des clés à partir des trailers d'un dump chargé depuis
/// un .mfd (cf. [`dump_to_mfd_with_keys`]). KeyA = bytes [0..6], KeyB = [10..16].
/// Les clés nulles (00..00 = jamais injectées) sont ignorées.
pub fn keys_from_dump(dump: &MifareDump) -> Vec<SectorKey> {
    let mut out = Vec::new();
    let card_type = dump.card_type;
    for sector in 0..card_type.sector_count() {
        let trailer = match card_type.sector_trailer(sector) {
            Some(t) => t as usize,
            None => continue,
        };
        if trailer >= dump.blocks.len() || !dump.readable[trailer] {
            continue;
        }
        let blk = &dump.blocks[trailer];
        let key_a: [u8; 6] = blk[0..6].try_into().unwrap();
        if key_a != [0u8; 6] {
            out.push(SectorKey {
                sector,
                key_ab: 0,
                key: key_a,
            });
        }
        let key_b: [u8; 6] = blk[10..16].try_into().unwrap();
        if key_b != [0u8; 6] && key_b != key_a {
            out.push(SectorKey {
                sector,
                key_ab: 1,
                key: key_b,
            });
        }
    }
    out
}

pub fn dump_all_sectors<F: FnMut(u8, u8)>(
    pn532: &mut Pn532,
    uid: &NfcUid,
    mut on_sector: F,
) -> (Box<MifareDump>, Vec<SectorKey>) {
    let card_type = ClassicType::from_sak(uid.sak).unwrap_or(ClassicType::Classic1K);
    let mut dump = Box::new(MifareDump::new(card_type));
    let uid4 = uid_to_4bytes(uid);
    let total = card_type.sector_count();

    log::info!("╔══════════════════════════════════════════╗");
    log::info!("║       MIFARE CLASSIC — DICT ATTACK       ║");
    log::info!("╠══════════════════════════════════════════╣");
    log::info!(
        "║ UID  : {:02X}:{:02X}:{:02X}:{:02X}                      ║",
        uid.bytes[0],
        uid.bytes[1],
        uid.bytes[2],
        uid.bytes[3]
    );
    log::info!(
        "║ SAK  : 0x{:02X}  ATQA: {:02X}{:02X}                  ║",
        uid.sak,
        uid.atqa[1],
        uid.atqa[0]
    );
    log::info!(
        "║ Type : {:?}   {} sec   {} blocs         ║",
        card_type,
        total,
        card_type.block_count()
    );
    log::info!(
        "║ Dico : {} cles                           ║",
        DEFAULT_KEYS.len()
    );
    log::info!("╚══════════════════════════════════════════╝");

    let mut found_sectors = 0u8;
    let mut found_keys: Vec<SectorKey> = Vec::new();

    for sector in 0..total {
        on_sector(sector, total);
        let trailer = card_type.sector_trailer(sector).unwrap();

        log::info!(
            "┌─ Secteur {:02}/{} ───────────────────────────",
            sector,
            total - 1
        );

        match try_sector(pn532, &mut dump, sector, trailer, &uid4, &mut found_keys) {
            Some(true) => {
                found_sectors += 1;
            }
            Some(false) => {}
            None => {
                log::warn!("└─ Secteur {:02}: Carte absente — dump abandonne", sector);
                break;
            }
        }
    }

    let readable = dump.readable_count();
    let total_blocks = dump.total_blocks();

    log::info!("╔══════════════════════════════════════════╗");
    log::info!("║              DUMP TERMINE                ║");
    log::info!("╠══════════════════════════════════════════╣");
    log::info!(
        "║ Secteurs lus : {:02}/{:02}                      ║",
        found_sectors,
        total
    );
    log::info!(
        "║ Blocs lus    : {:03}/{:03}                     ║",
        readable,
        total_blocks
    );
    log::info!("╚══════════════════════════════════════════╝");

    (dump, found_keys)
}

/// Retourne `None` si la carte a quitté le champ (dump doit s'arrêter),
/// `Some(true/false)` si le secteur a pu/n'a pas pu être lu.
fn try_sector(
    pn532: &mut Pn532,
    dump: &mut MifareDump,
    sector: u8,
    trailer: u8,
    uid4: &[u8; 4],
    found_keys: &mut Vec<SectorKey>,
) -> Option<bool> {
    // ── Phase 0 : réutilise les clés déjà trouvées (dédupliquées par valeur) ──
    // Optimisation critique : si tous les secteurs partagent la même clé, le
    // dict complet (238 essais × ~280 ms) n'est tenté qu'une seule fois au lieu
    // de 16.  Réduit le temps de dump d'~2 min à ~10 s sur les badges monoclé.
    {
        let snapshot: Vec<SectorKey> = found_keys.to_vec();
        let mut tried: Vec<([u8; 6], u8)> = Vec::new();
        for sk in &snapshot {
            let key_id = (sk.key, sk.key_ab);
            if tried.contains(&key_id) {
                continue;
            }
            tried.push(key_id);
            let auth_cmd = if sk.key_ab == 0 {
                MIFARE_AUTH_A
            } else {
                MIFARE_AUTH_B
            };
            if pn532.mifare_auth(trailer, auth_cmd, &sk.key, uid4).is_ok() {
                log::info!(
                    "│  [Key{} cache {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}] → OK ✓ (sec {:02})",
                    if sk.key_ab == 0 { "A" } else { "B" },
                    sk.key[0],
                    sk.key[1],
                    sk.key[2],
                    sk.key[3],
                    sk.key[4],
                    sk.key[5],
                    sk.sector
                );
                found_keys.push(SectorKey {
                    sector,
                    key_ab: sk.key_ab,
                    key: sk.key,
                });
                read_sector_blocks(pn532, dump, sector);
                log::info!(
                    "└─ Secteur {:02}: OK ({} blocs)",
                    sector,
                    dump_sector_block_count(dump, sector)
                );
                return Some(true);
            }
            if !re_select_with_retry(pn532) {
                log::warn!("│  Carte perdue (cache key)");
                return None;
            }
        }
    }

    let n = DEFAULT_KEYS.len();

    // ── Phase 1 : KeyA — dict complet ─────────────────────────────────────
    log::info!("│ [KeyA] dict {} cles (trailer={:03})", n, trailer);
    for (i, key) in DEFAULT_KEYS.iter().enumerate() {
        let ok = pn532.mifare_auth(trailer, MIFARE_AUTH_A, key, uid4).is_ok();
        if ok {
            log::info!(
                "│  A [{:02}/{}] {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} → OK ✓",
                i + 1,
                n,
                key[0],
                key[1],
                key[2],
                key[3],
                key[4],
                key[5]
            );
            found_keys.push(SectorKey {
                sector,
                key_ab: 0,
                key: *key,
            });
            read_sector_blocks(pn532, dump, sector);
            log::info!(
                "└─ Secteur {:02}: OK ({} blocs)",
                sector,
                dump_sector_block_count(dump, sector)
            );
            return Some(true);
        }
        log::debug!(
            "│  A [{:02}/{}] {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} → FAIL",
            i + 1,
            n,
            key[0],
            key[1],
            key[2],
            key[3],
            key[4],
            key[5]
        );
        // Battement de progression visible en INFO : sans ça, le dict complet
        // d'un secteur protégé reste ~100 s sans aucun log → on ne sait pas si
        // le device bosse ou s'il a planté.
        if (i + 1) % PROGRESS_EVERY == 0 {
            log::info!("│  KeyA … {}/{} cles testees (en cours)", i + 1, n);
        }
        if !re_select_with_retry(pn532) {
            log::warn!(
                "│  Carte perdue apres {} tentatives re_select",
                RE_SELECT_RETRIES
            );
            return None;
        }
    }

    // ── Phase 2 : KeyB — dict complet ─────────────────────────────────────
    log::info!("│ [KeyB] dict {} cles (trailer={:03})", n, trailer);
    for (i, key) in DEFAULT_KEYS.iter().enumerate() {
        let ok = pn532.mifare_auth(trailer, MIFARE_AUTH_B, key, uid4).is_ok();
        if ok {
            log::info!(
                "│  B [{:02}/{}] {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} → OK ✓",
                i + 1,
                n,
                key[0],
                key[1],
                key[2],
                key[3],
                key[4],
                key[5]
            );
            found_keys.push(SectorKey {
                sector,
                key_ab: 1,
                key: *key,
            });
            read_sector_blocks(pn532, dump, sector);
            log::info!(
                "└─ Secteur {:02}: OK ({} blocs)",
                sector,
                dump_sector_block_count(dump, sector)
            );
            return Some(true);
        }
        log::debug!(
            "│  B [{:02}/{}] {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} → FAIL",
            i + 1,
            n,
            key[0],
            key[1],
            key[2],
            key[3],
            key[4],
            key[5]
        );
        if (i + 1) % PROGRESS_EVERY == 0 {
            log::info!("│  KeyB … {}/{} cles testees (en cours)", i + 1, n);
        }
        if !re_select_with_retry(pn532) {
            log::warn!(
                "│  Carte perdue apres {} tentatives re_select",
                RE_SELECT_RETRIES
            );
            return None;
        }
    }

    log::warn!("└─ Secteur {:02}: ECHEC — aucune cle valide", sector);
    Some(false)
}

fn re_select_with_retry(pn532: &mut Pn532) -> bool {
    for attempt in 0..RE_SELECT_RETRIES {
        if pn532.re_select() {
            return true;
        }
        log::debug!("re_select {}/{} echouee", attempt + 1, RE_SELECT_RETRIES);
    }
    log::warn!(
        "re_select: carte hors champ apres {} essais",
        RE_SELECT_RETRIES
    );
    false
}

fn read_sector_blocks(pn532: &mut Pn532, dump: &mut MifareDump, sector: u8) {
    let card_type = dump.card_type;
    let first = match card_type.sector_first_block(sector) {
        Some(b) => b,
        None => return,
    };
    let count = card_type.sector_block_count(sector);
    for i in 0..count {
        let block = first + i;
        let idx = block as usize;
        match pn532.mifare_read_block(block) {
            Ok(data) => {
                dump.blocks[idx] = data;
                dump.readable[idx] = true;
                log::info!(
                    "│  BLK {:03}: {:02X} {:02X} {:02X} {:02X}  {:02X} {:02X} {:02X} {:02X}  {:02X} {:02X} {:02X} {:02X}  {:02X} {:02X} {:02X} {:02X}",
                    block,
                    data[0],  data[1],  data[2],  data[3],
                    data[4],  data[5],  data[6],  data[7],
                    data[8],  data[9],  data[10], data[11],
                    data[12], data[13], data[14], data[15]
                );
            }
            Err(e) => {
                log::warn!("│  BLK {:03}: ERREUR {:?}", block, e);
            }
        }
    }
}

fn dump_sector_block_count(dump: &MifareDump, sector: u8) -> u8 {
    let card_type = dump.card_type;
    let first = card_type.sector_first_block(sector).unwrap_or(0) as usize;
    let count = card_type.sector_block_count(sector) as usize;
    dump.readable[first..first + count]
        .iter()
        .filter(|&&r| r)
        .count() as u8
}

fn uid_to_4bytes(uid: &NfcUid) -> [u8; 4] {
    [
        uid.bytes.get(0).copied().unwrap_or(0),
        uid.bytes.get(1).copied().unwrap_or(0),
        uid.bytes.get(2).copied().unwrap_or(0),
        uid.bytes.get(3).copied().unwrap_or(0),
    ]
}
