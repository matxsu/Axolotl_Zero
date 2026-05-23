//! Attaques MIFARE Classic : dump par dictionnaire de clés.
//!
//! Supporte 1K (16 secteurs × 4 blocs = 64 blocs) et 4K (40 secteurs : 32 × 4 blocs
//! puis 8 × 16 blocs = 256 blocs). La math secteur/bloc est déléguée à
//! `axolotl_core::layout::ClassicType` (testé sur host).

use axolotl_core::{
    keys::DEFAULT_KEYS,
    layout::ClassicType,
    protocol::{MIFARE_AUTH_A, MIFARE_AUTH_B},
    MifareDump, NfcUid,
};

use super::Pn532;

const RE_SELECT_RETRIES: u8 = 5;

/// Dump complet d'une carte MIFARE Classic.
/// Le type (1K/4K/Mini) est déduit du SAK ; à défaut on assume 1K.
/// `on_sector(n)` est appelé au début de chaque secteur (0..sector_count-1).
pub fn dump_all_sectors<F: FnMut(u8, u8)>(
    pn532: &mut Pn532,
    uid: &NfcUid,
    mut on_sector: F,
) -> Box<MifareDump> {
    let card_type = ClassicType::from_sak(uid.sak).unwrap_or(ClassicType::Classic1K);
    let mut dump = Box::new(MifareDump::new(card_type));
    let uid4 = uid_to_4bytes(uid);
    let total = card_type.sector_count();

    log::info!(
        "Dump : {:?}, {} secteurs, {} blocs",
        card_type,
        total,
        card_type.block_count()
    );

    for sector in 0..total {
        on_sector(sector, total);
        // sector_trailer ne panique pas car on itère dans la plage valide
        let trailer = card_type.sector_trailer(sector).unwrap();
        if !try_sector(pn532, &mut dump, sector, trailer, &uid4) {
            log::warn!("Secteur {:02}: aucune cle trouvee", sector);
        }
    }
    dump
}

/// Essaie toutes les clés (KeyA d'abord, KeyB ensuite) pour un secteur.
/// Retourne `true` si le secteur a pu être lu.
fn try_sector(
    pn532: &mut Pn532,
    dump: &mut MifareDump,
    sector: u8,
    trailer: u8,
    uid4: &[u8; 4],
) -> bool {
    for key in DEFAULT_KEYS {
        if pn532.mifare_auth(trailer, MIFARE_AUTH_A, key, uid4).is_ok() {
            log::info!("Secteur {:02}: KeyA {:02X?} OK", sector, key);
            read_sector_blocks(pn532, dump, sector);
            return true;
        }
        if !re_select_with_retry(pn532) {
            return false;
        }
    }

    for key in DEFAULT_KEYS {
        if pn532.mifare_auth(trailer, MIFARE_AUTH_B, key, uid4).is_ok() {
            log::info!("Secteur {:02}: KeyB {:02X?} OK", sector, key);
            read_sector_blocks(pn532, dump, sector);
            return true;
        }
        if !re_select_with_retry(pn532) {
            return false;
        }
    }

    false
}

/// Re-sélection avec plusieurs tentatives — la carte peut mettre du temps à
/// répondre après un cycle RF.
fn re_select_with_retry(pn532: &mut Pn532) -> bool {
    for attempt in 0..RE_SELECT_RETRIES {
        if pn532.re_select() {
            return true;
        }
        log::debug!(
            "re_select tentative {}/{} echouee",
            attempt + 1,
            RE_SELECT_RETRIES
        );
    }
    log::warn!(
        "re_select: carte non detectee apres {} essais",
        RE_SELECT_RETRIES
    );
    false
}

/// Lit tous les blocs d'un secteur (le secteur doit être authentifié).
/// Le nombre de blocs dépend du secteur (4 pour 1K/4K secteurs 0-31, 16 pour 4K 32-39).
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
            }
            Err(e) => {
                log::warn!("Read bloc {}: {:?}", block, e);
            }
        }
    }
}

/// Extrait les 4 premiers bytes de l'UID (requis par MIFARE Classic auth).
fn uid_to_4bytes(uid: &NfcUid) -> [u8; 4] {
    [
        uid.bytes.get(0).copied().unwrap_or(0),
        uid.bytes.get(1).copied().unwrap_or(0),
        uid.bytes.get(2).copied().unwrap_or(0),
        uid.bytes.get(3).copied().unwrap_or(0),
    ]
}
