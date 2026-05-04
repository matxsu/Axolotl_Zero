//! Attaques MIFARE Classic : dump par dictionnaire de clés.
//!
//! Pour chaque secteur (0..16), on tente toutes les clés du dictionnaire
//! en KeyA puis KeyB. Dès qu'une clé ouvre le secteur, on lit les 4 blocs
//! et on passe au secteur suivant.

use super::dump::MifareDump;
use super::keys::DEFAULT_KEYS;
use super::mifare::{MIFARE_AUTH_A, MIFARE_AUTH_B};
use super::{NfcUid, Pn532};

/// Tente de dumper une carte MIFARE Classic 1K.
/// Retourne un `MifareDump` dont les champs `readable` indiquent
/// quels blocs ont pu être lus.
pub fn dump_all_sectors(pn532: &mut Pn532, uid: &NfcUid) -> MifareDump {
    let mut dump = MifareDump::new();
    let uid4 = uid_to_4bytes(uid);

    for sector in 0u8..16 {
        let trailer = sector * 4 + 3;
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
    // --- Tentative KeyA ---
    for key in DEFAULT_KEYS {
        if pn532.mifare_auth(trailer, MIFARE_AUTH_A, key, uid4).is_ok() {
            log::info!("Secteur {:02}: KeyA {:02X?} OK", sector, key);
            read_sector_blocks(pn532, dump, sector);
            return true;
        }
        // Après un auth raté la carte est HALTée — re-sélection obligatoire
        if !pn532.re_select() {
            return false; // carte retirée
        }
    }

    // --- Tentative KeyB ---
    for key in DEFAULT_KEYS {
        if pn532.mifare_auth(trailer, MIFARE_AUTH_B, key, uid4).is_ok() {
            log::info!("Secteur {:02}: KeyB {:02X?} OK", sector, key);
            read_sector_blocks(pn532, dump, sector);
            return true;
        }
        if !pn532.re_select() {
            return false;
        }
    }

    false
}

/// Lit les 4 blocs d'un secteur (le secteur doit être authentifié).
fn read_sector_blocks(pn532: &mut Pn532, dump: &mut MifareDump, sector: u8) {
    let base = (sector * 4) as usize;
    for i in 0..4usize {
        let block = (base + i) as u8;
        match pn532.mifare_read_block(block) {
            Ok(data) => {
                dump.blocks[base + i] = data;
                dump.readable[base + i] = true;
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
