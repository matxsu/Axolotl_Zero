//! Module NFC — Driver PN532 (I²C) + MIFARE Classic dump
//!
//! Protocole I²C PN532 (AN10609 §6.2.4) :
//!   PREAMBLE + START_CODE + LEN + LCS + TFI + DATA + DCS + POSTAMBLE
//!   Lecture : lire 1 byte RDY (0x01 = prêt) puis lire la trame réponse.

use esp_idf_hal::{delay::FreeRtos, delay::BLOCK, i2c::I2cDriver};

pub mod attacks;

// Re-exports depuis axolotl-core pour que main.rs puisse écrire `nfc::NfcUid`
// sans changer ses imports actuels.
pub use axolotl_core::{card::NfcUid, dump::MifareDump, layout::ClassicType};

use axolotl_core::protocol::{MIFARE_AUTH_A, MIFARE_READ, MIFARE_UL_WRITE, MIFARE_WRITE};

// ── Adresse I²C ────────────────────────────────────────────────────────────
const PN532_ADDR: u8 = 0x24;

// ── Commandes PN532 ────────────────────────────────────────────────────────
const CMD_GET_FIRMWARE_VERSION: u8 = 0x02;
const CMD_SAM_CONFIGURATION: u8 = 0x14;
const CMD_IN_LIST_PASSIVE_TARGET: u8 = 0x4A;
const CMD_IN_DATA_EXCHANGE: u8 = 0x40;
const CMD_IN_RELEASE: u8 = 0x52;
const CMD_RF_CONFIGURATION: u8 = 0x32;

// ── Framing ────────────────────────────────────────────────────────────────
const PREAMBLE: u8 = 0x00;
const START1: u8 = 0x00;
const START2: u8 = 0xFF;
const POSTAMBLE: u8 = 0x00;
const TFI_H2C: u8 = 0xD4; // Host → PN532
const TFI_C2H: u8 = 0xD5; // PN532 → Host

// ── Struct ─────────────────────────────────────────────────────────────────

pub struct Pn532<'d> {
    i2c: I2cDriver<'d>,
}

// ── Init ───────────────────────────────────────────────────────────────────

impl<'d> Pn532<'d> {
    pub fn new(i2c: I2cDriver<'d>) -> anyhow::Result<Self> {
        let mut pn532 = Self { i2c };
        FreeRtos::delay_ms(500);

        // Wakeup : 0x55 × 16 pour sortir le PN532 du power-down
        let wakeup = [0x55u8; 16];
        let _ = pn532.i2c.write(PN532_ADDR, &wakeup, BLOCK);
        FreeRtos::delay_ms(100);

        // Flush du bus I²C (stabilisation)
        for _ in 0..10 {
            let mut rdy = [0u8; 1];
            let _ = pn532.i2c.read(PN532_ADDR, &mut rdy, BLOCK);
            FreeRtos::delay_ms(20);
        }
        FreeRtos::delay_ms(100);

        let ver = pn532.get_firmware_version()?;
        log::info!(
            "PN532 OK — IC={:#02x} Ver={} Rev={}",
            ver[0],
            ver[1],
            ver[2]
        );

        pn532.sam_configuration()?;
        log::info!("PN532 pret");
        Ok(pn532)
    }

    // ── Primitives I²C / framing ──────────────────────────────────────────

    /// Construit et envoie une trame PN532 complète avec checksums.
    fn send_frame(&mut self, cmd: u8, params: &[u8]) -> anyhow::Result<()> {
        let data_len = 2 + params.len(); // TFI + CMD + params
        let lcs = (!(data_len as u8)).wrapping_add(1);

        let mut sum = TFI_H2C.wrapping_add(cmd);
        for &b in params {
            sum = sum.wrapping_add(b);
        }
        let dcs = (!sum).wrapping_add(1);

        let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
        frame.push(PREAMBLE).ok();
        frame.push(START1).ok();
        frame.push(START2).ok();
        frame.push(data_len as u8).ok();
        frame.push(lcs).ok();
        frame.push(TFI_H2C).ok();
        frame.push(cmd).ok();
        for &b in params {
            frame.push(b).ok();
        }
        frame.push(dcs).ok();
        frame.push(POSTAMBLE).ok();

        self.i2c
            .write(PN532_ADDR, &frame, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 write: {:?}", e))
    }

    /// Attend l'ACK du PN532 (6 bytes : 00 00 FF 00 FF 00).
    fn read_ack(&mut self) -> anyhow::Result<()> {
        self.wait_ready(50)?;
        let mut ack = [0u8; 7]; // RDY(1) + ACK(6)
        self.i2c
            .read(PN532_ADDR, &mut ack, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read ACK: {:?}", e))
    }

    /// Lit la réponse PN532, retourne les bytes de données (après TFI + CMD+1).
    fn read_response(&mut self, cmd: u8) -> anyhow::Result<heapless::Vec<u8, 32>> {
        self.wait_ready(100)?;
        let mut buf = [0u8; 32];
        self.i2c
            .read(PN532_ADDR, &mut buf, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read resp: {:?}", e))?;

        // buf[0]=RDY  buf[1]=PRE  buf[2]=S1  buf[3]=S2
        // buf[4]=LEN  buf[5]=LCS  buf[6]=TFI buf[7]=CMD+1  buf[8..]=DATA
        if buf[6] != TFI_C2H {
            return Err(anyhow::anyhow!("PN532 TFI inattendu: {:#02x}", buf[6]));
        }
        if buf[7] != cmd.wrapping_add(1) {
            return Err(anyhow::anyhow!("PN532 cmd inattendue: {:#02x}", buf[7]));
        }
        let len = buf[4] as usize;
        let data_start = 8usize;
        let data_end = (data_start + len.saturating_sub(2)).min(32);

        let mut result: heapless::Vec<u8, 32> = heapless::Vec::new();
        for i in data_start..data_end {
            result.push(buf[i]).ok();
        }
        Ok(result)
    }

    /// Attend RDY == 0x01, max_tries × 10 ms.
    fn wait_ready(&mut self, max_tries: u32) -> anyhow::Result<()> {
        for _ in 0..max_tries {
            let mut rdy = [0u8; 1];
            if self.i2c.read(PN532_ADDR, &mut rdy, BLOCK).is_ok() && rdy[0] == 0x01 {
                return Ok(());
            }
            FreeRtos::delay_ms(10);
        }
        Err(anyhow::anyhow!("PN532 timeout"))
    }

    fn get_firmware_version(&mut self) -> anyhow::Result<[u8; 3]> {
        self.send_frame(CMD_GET_FIRMWARE_VERSION, &[])?;
        self.read_ack()?;
        let resp = self.read_response(CMD_GET_FIRMWARE_VERSION)?;
        Ok([
            resp.get(0).copied().unwrap_or(0),
            resp.get(1).copied().unwrap_or(0),
            resp.get(2).copied().unwrap_or(0),
        ])
    }

    fn sam_configuration(&mut self) -> anyhow::Result<()> {
        self.send_frame(CMD_SAM_CONFIGURATION, &[0x01, 0x14, 0x01])?;
        self.read_ack()?;
        self.read_response(CMD_SAM_CONFIGURATION)?;
        Ok(())
    }

    // ── API publique — scan ───────────────────────────────────────────────

    /// Scan ISO14443A — retourne l'UID si une carte est présente.
    pub fn read_uid(&mut self) -> anyhow::Result<Option<NfcUid>> {
        self.send_frame(CMD_IN_LIST_PASSIVE_TARGET, &[0x01, 0x00])?;
        self.read_ack()?;

        if self.wait_ready(30).is_err() {
            return Ok(None);
        }

        let mut buf = [0u8; 32];
        self.i2c
            .read(PN532_ADDR, &mut buf, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read UID: {:?}", e))?;

        // buf[8]=NbTg  buf[9]=Tg  buf[10..11]=ATQA  buf[12]=SAK
        // buf[13]=NIDLen  buf[14..]=UID
        if buf[8] == 0 {
            return Ok(None);
        }
        let uid_len = buf[13] as usize;
        if uid_len == 0 || uid_len > 7 {
            return Ok(None);
        }

        let mut uid = NfcUid {
            bytes: [0u8; 7],
            len: uid_len,
            atqa: [buf[10], buf[11]],
            sak: buf[12],
        };
        for i in 0..uid_len {
            uid.bytes[i] = buf[14 + i];
        }
        Ok(Some(uid))
    }

    // ── MIFARE Classic — méthodes privées ────────────────────────────────

    /// Authentifie un secteur avec la clé donnée (KeyA ou KeyB).
    /// Retourne `Ok(())` si l'auth réussit, `Err` sinon.
    fn mifare_auth(
        &mut self,
        block: u8,
        auth_cmd: u8, // MIFARE_AUTH_A (0x60) ou MIFARE_AUTH_B (0x61)
        key: &[u8; 6],
        uid4: &[u8; 4],
    ) -> anyhow::Result<()> {
        let params: [u8; 13] = [
            0x01, // Tg
            auth_cmd, block, key[0], key[1], key[2], key[3], key[4], key[5], uid4[0], uid4[1],
            uid4[2], uid4[3],
        ];
        self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
        let status = resp.get(0).copied().unwrap_or(0xFF);
        if status != 0x00 {
            return Err(anyhow::anyhow!("auth echec: {:#02x}", status));
        }
        Ok(())
    }

    /// Lit un bloc MIFARE Classic (16 bytes). Le secteur doit être authentifié.
    fn mifare_read_block(&mut self, block: u8) -> anyhow::Result<[u8; 16]> {
        let params: [u8; 3] = [0x01, MIFARE_READ, block];
        self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
        let status = resp.get(0).copied().unwrap_or(0xFF);
        if status != 0x00 {
            return Err(anyhow::anyhow!("read_block echec: {:#02x}", status));
        }
        let mut data = [0u8; 16];
        for i in 0..16 {
            data[i] = resp.get(i + 1).copied().unwrap_or(0);
        }
        Ok(data)
    }

    /// Écrit 16 bytes dans un bloc MIFARE Classic. Le secteur doit être authentifié.
    /// Le bloc 0 (UID + fabricant) est ignoré — il est en lecture seule sur les cartes
    /// standard (sauf cartes "magic" UID-modifiable).
    fn mifare_write_block(&mut self, block: u8, data: &[u8; 16]) -> anyhow::Result<()> {
        let mut params = [0u8; 19]; // Tg(1) + WRITE(1) + block(1) + data(16)
        params[0] = 0x01;
        params[1] = MIFARE_WRITE;
        params[2] = block;
        params[3..19].copy_from_slice(data);
        self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
        let status = resp.get(0).copied().unwrap_or(0xFF);
        if status != 0x00 {
            return Err(anyhow::anyhow!("write_block echec: {:#02x}", status));
        }
        Ok(())
    }

    /// Libère la cible courante (InRelease).
    /// Nécessaire après un auth raté avant de retenter (carte en HALT).
    fn in_release(&mut self) {
        let _ = self.send_frame(CMD_IN_RELEASE, &[0x01]);
        if self.read_ack().is_ok() {
            let _ = self.read_response(CMD_IN_RELEASE);
        }
        FreeRtos::delay_ms(20);
    }

    /// Re-sélectionne la carte après un auth raté.
    ///
    /// Problème : `InRelease` (0x52) envoie HLTA à la carte → carte passe en
    /// état HALT. `InListPassiveTarget` n'envoie que REQA (0x26) qui est ignoré
    /// par les cartes HALT → re_select échoue toujours.
    ///
    /// Fix : cycle RF (off → on) après InRelease. La carte perd l'alimentation,
    /// son état HALT est effacé. Au rallumage elle revient en IDLE et répond à REQA.
    fn re_select(&mut self) -> bool {
        self.in_release();

        // RF OFF : On coupe le champ pendant 300ms.
        // C'est le temps nécessaire pour que le condensateur du badge Comelit se vide.
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x01, 0x00]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);

        FreeRtos::delay_ms(300);

        // RF ON : On rallume avec 0x02 (allumage forcé du champ)
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x01, 0x02]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);

        FreeRtos::delay_ms(150); // Stabilisation

        // On tente 10 fois de suite de retrouver l'UID (on est très persistant)
        for i in 0..10 {
            if matches!(self.read_uid(), Ok(Some(_))) {
                log::info!("Badge réveillé (tentative {})", i + 1);
                return true;
            }
            FreeRtos::delay_ms(100);
        }
        false
    }

    // ── API publique — restore MIFARE ────────────────────────────────────

    /// Écrit un dump complet sur la carte cible (clone).
    /// - Saute le bloc 0 (UID/fabricant, read-only sur cartes standard).
    /// - Saute les sector trailers (blocs 3, 7, 11, ... 63) pour ne pas
    ///   écraser les clés et access bits de la carte cible.
    /// - `on_sector(sector)` : callback de progression (0..15).
    /// Retourne le nombre de blocs écrits avec succès.
    pub fn mifare_restore<F: FnMut(u8, u8)>(
        &mut self,
        uid: &NfcUid,
        dump: &MifareDump,
        mut on_sector: F,
    ) -> anyhow::Result<u32> {
        let uid4 = [uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]];
        let mut written = 0u32;
        let card_type = dump.card_type;
        let total = card_type.sector_count();

        for sector in 0..total {
            on_sector(sector, total);
            let trailer = match card_type.sector_trailer(sector) {
                Some(t) => t,
                None => break,
            };
            let first = card_type.sector_first_block(sector).unwrap();
            let block_count = card_type.sector_block_count(sector);

            // Authentification avec la clé A du dump (sector trailer bloc)
            let key_a: [u8; 6] = dump.blocks[trailer as usize][0..6]
                .try_into()
                .unwrap_or([0xFF; 6]);

            if self.mifare_auth(trailer, MIFARE_AUTH_A, &key_a, &uid4).is_err() {
                log::warn!("Restore secteur {:02}: auth echouee", sector);
                if !self.re_select() {
                    return Err(anyhow::anyhow!("carte perdue au secteur {}", sector));
                }
                continue;
            }

            // Écrit tous les blocs du secteur SAUF le trailer (préserve clés cible)
            for i in 0..(block_count - 1) {
                let block = first + i;
                let idx = block as usize;
                // Bloc 0 = UID/fabricant, read-only sur cartes standard
                if block == 0 {
                    continue;
                }
                if !dump.readable[idx] {
                    continue;
                }
                match self.mifare_write_block(block, &dump.blocks[idx]) {
                    Ok(_) => written += 1,
                    Err(e) => log::warn!("Restore bloc {:02}: {:?}", block, e),
                }
            }

            self.re_select();
        }

        log::info!("Restore termine : {} blocs ecrits", written);
        Ok(written)
    }

    // ── API publique — dump MIFARE ────────────────────────────────────────

    /// Dump complet d'une carte MIFARE Classic par attaque dictionnaire.
    /// Détecte 1K/4K via SAK ; on_sector(n) appelé au début de chaque secteur.
    pub fn mifare_dump<F: FnMut(u8, u8)>(
        &mut self,
        uid: &NfcUid,
        on_sector: F,
    ) -> anyhow::Result<Box<MifareDump>> {
        log::info!("Debut dump MIFARE Classic ({})...", uid.card_type());
        let dump = attacks::dump_all_sectors(self, uid, on_sector);
        log::info!(
            "Dump termine : {}/{} blocs lus",
            dump.readable_count(),
            dump.total_blocks()
        );
        Ok(dump)
    }

    // ── API publique — Ultralight / NTAG ─────────────────────────────────

    /// Lit les 16 premières pages (64 bytes) d'une carte Ultralight/NTAG.
    /// Pas d'authentification — la carte est déjà sélectionnée par read_uid.
    /// La commande MIFARE READ (0x30) retourne 4 pages (16 bytes) par appel,
    /// donc on fait 4 lectures aux pages 0, 4, 8, 12.
    pub fn ultralight_read_all(&mut self) -> anyhow::Result<[u8; 64]> {
        let mut data = [0u8; 64];
        for chunk in 0u8..4 {
            let start_page = chunk * 4;
            let params: [u8; 3] = [0x01, MIFARE_READ, start_page];
            self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
            self.read_ack()?;
            let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
            let status = resp.get(0).copied().unwrap_or(0xFF);
            if status != 0x00 {
                return Err(anyhow::anyhow!(
                    "UL read page {}: status {:#02x}",
                    start_page,
                    status
                ));
            }
            let offset = (chunk as usize) * 16;
            for i in 0..16 {
                data[offset + i] = resp.get(i + 1).copied().unwrap_or(0);
            }
        }
        log::info!("UL/NTAG: 64 bytes lus");
        Ok(data)
    }

    /// Lit une seule page (4 bytes) Ultralight/NTAG via la commande READ.
    /// La carte retourne en réalité 4 pages, on ne garde que la première.
    pub fn ultralight_read_page(&mut self, page: u8) -> anyhow::Result<[u8; 4]> {
        let params: [u8; 3] = [0x01, MIFARE_READ, page];
        self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
        let status = resp.get(0).copied().unwrap_or(0xFF);
        if status != 0x00 {
            return Err(anyhow::anyhow!("UL read page {}: {:#02x}", page, status));
        }
        Ok([
            resp.get(1).copied().unwrap_or(0),
            resp.get(2).copied().unwrap_or(0),
            resp.get(3).copied().unwrap_or(0),
            resp.get(4).copied().unwrap_or(0),
        ])
    }

    /// Écrit 4 bytes (1 page) Ultralight/NTAG via la commande WRITE (0xA2).
    /// Attention : sur NTAG les pages 0..3 sont read-only (UID + capability container).
    /// Les pages user data commencent à 4.
    pub fn ultralight_write_page(&mut self, page: u8, data: &[u8; 4]) -> anyhow::Result<()> {
        let params: [u8; 7] = [
            0x01,
            MIFARE_UL_WRITE,
            page,
            data[0],
            data[1],
            data[2],
            data[3],
        ];
        self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
        let status = resp.get(0).copied().unwrap_or(0xFF);
        if status != 0x00 {
            return Err(anyhow::anyhow!("UL write page {}: {:#02x}", page, status));
        }
        Ok(())
    }

    /// Détecte la taille mémoire d'une carte NTAG via le Capability Container (page 3).
    /// CC byte 2 contient la capacité en unités de 8 bytes : 0x12=NTAG213, 0x3E=NTAG215, 0x6F=NTAG216.
    /// Retourne le nombre total de pages lisibles (user data + lock).
    /// Sur Ultralight classique le CC est différent, on retombe sur 16 pages.
    pub fn ntag_detect_pages(&mut self) -> anyhow::Result<u8> {
        let page3 = self.ultralight_read_page(3)?;
        // CC structure: [magic, version, size, access]
        // NTAG213: size=0x12 → 144 bytes user → 45 pages totales (4..39 data + lock)
        // NTAG215: size=0x3E → 504 bytes user → 135 pages
        // NTAG216: size=0x6F → 888 bytes user → 231 pages
        let pages = match page3[2] {
            0x12 => 45,
            0x3E => 135,
            0x6F => 231,
            _ => 16, // Ultralight classique ou CC inconnu
        };
        log::info!(
            "NTAG CC: {:02X} {:02X} {:02X} {:02X} -> {} pages",
            page3[0],
            page3[1],
            page3[2],
            page3[3],
            pages
        );
        Ok(pages)
    }

    /// Écrit un dump Ultralight/NTAG sur la carte cible courante.
    /// Saute les pages 0..3 (UID + lock + CC, read-only sur cartes standard).
    /// `on_page(page, total_pages)` : callback de progression.
    /// Retourne le nombre de pages écrites avec succès.
    pub fn ultralight_clone<F: FnMut(u8, u8)>(
        &mut self,
        data: &[u8],
        mut on_page: F,
    ) -> anyhow::Result<u32> {
        let total_pages = (data.len() / 4) as u8;
        const FIRST_WRITABLE: u8 = 4; // pages 0..3 = UID/lock/CC (read-only)
        let mut written = 0u32;

        for page in FIRST_WRITABLE..total_pages {
            on_page(page, total_pages);
            let off = page as usize * 4;
            if off + 4 > data.len() {
                break;
            }
            let chunk: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
            match self.ultralight_write_page(page, &chunk) {
                Ok(_) => written += 1,
                Err(e) => log::warn!("UL clone page {}: {:?}", page, e),
            }
        }
        log::info!("UL clone : {} pages ecrites", written);
        Ok(written)
    }

    /// Lit toutes les pages d'un NTAG/Ultralight (4 bytes par page).
    /// Auto-détecte la taille via CC. La commande READ (0x30) renvoie 4 pages
    /// donc on fait des reads par chunk de 4.
    pub fn ntag_read_full(&mut self) -> anyhow::Result<Vec<u8>> {
        let total_pages = self.ntag_detect_pages()?;
        let mut data = vec![0u8; total_pages as usize * 4];
        let mut page = 0u8;
        while page < total_pages {
            let params: [u8; 3] = [0x01, MIFARE_READ, page];
            self.send_frame(CMD_IN_DATA_EXCHANGE, &params)?;
            self.read_ack()?;
            let resp = self.read_response(CMD_IN_DATA_EXCHANGE)?;
            let status = resp.get(0).copied().unwrap_or(0xFF);
            if status != 0x00 {
                log::warn!("NTAG read page {} stop: {:#02x}", page, status);
                break;
            }
            // Réponse = 16 bytes (4 pages). Copie ce qu'on peut.
            let max_bytes = ((total_pages - page) as usize * 4).min(16);
            let off = page as usize * 4;
            for i in 0..max_bytes {
                data[off + i] = resp.get(i + 1).copied().unwrap_or(0);
            }
            page = page.saturating_add(4);
        }
        log::info!("NTAG: {} pages ({} bytes) lus", total_pages, data.len());
        Ok(data)
    }
}

// ── Helpers de logging — print_log restait dans le firmware (log crate) ────

/// Log un dump MIFARE Classic ligne par ligne.
/// Logique de présentation, gardée côté firmware (la struct est dans core).
pub fn print_dump_log(dump: &MifareDump) {
    let total = dump.total_blocks();
    log::info!(
        "=== MIFARE Dump : {}/{} blocs lisibles ===",
        dump.readable_count(),
        total
    );
    for block in 0..total {
        if dump.readable[block] {
            let d = &dump.blocks[block];
            log::info!(
                "Bloc {:03}: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} \
                 {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                block,
                d[0], d[1], d[2], d[3],
                d[4], d[5], d[6], d[7],
                d[8], d[9], d[10], d[11],
                d[12], d[13], d[14], d[15]
            );
        } else {
            log::info!("Bloc {:03}: -- non lisible --", block);
        }
    }
}
