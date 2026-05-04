//! Module NFC — Driver PN532 (I²C) + MIFARE Classic dump
//!
//! Protocole I²C PN532 (AN10609 §6.2.4) :
//!   PREAMBLE + START_CODE + LEN + LCS + TFI + DATA + DCS + POSTAMBLE
//!   Lecture : lire 1 byte RDY (0x01 = prêt) puis lire la trame réponse.

use esp_idf_hal::{delay::FreeRtos, delay::BLOCK, i2c::I2cDriver};

pub mod attacks;
pub mod dump;
pub mod keys;
pub mod mifare;

pub use dump::MifareDump;

// ── Adresse I²C ────────────────────────────────────────────────────────────
const PN532_ADDR: u8 = 0x24;

// ── Commandes PN532 ────────────────────────────────────────────────────────
const CMD_GET_FIRMWARE_VERSION: u8 = 0x02;
const CMD_SAM_CONFIGURATION: u8 = 0x14;
const CMD_IN_LIST_PASSIVE_TARGET: u8 = 0x4A;
const CMD_IN_DATA_EXCHANGE: u8 = 0x40;
const CMD_IN_RELEASE: u8 = 0x52;

// ── Framing ────────────────────────────────────────────────────────────────
const PREAMBLE: u8 = 0x00;
const START1: u8 = 0x00;
const START2: u8 = 0xFF;
const POSTAMBLE: u8 = 0x00;
const TFI_H2C: u8 = 0xD4; // Host → PN532
const TFI_C2H: u8 = 0xD5; // PN532 → Host

// ── Commandes MIFARE Classic (utilisées en interne) ────────────────────────
use mifare::MIFARE_READ;

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
            ver[0], ver[1], ver[2]
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
            auth_cmd,
            block,
            key[0], key[1], key[2], key[3], key[4], key[5],
            uid4[0], uid4[1], uid4[2], uid4[3],
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
    /// Retourne `true` si la carte est toujours dans le champ RF.
    fn re_select(&mut self) -> bool {
        self.in_release();
        FreeRtos::delay_ms(30);
        matches!(self.read_uid(), Ok(Some(_)))
    }

    // ── API publique — dump MIFARE ────────────────────────────────────────

    /// Dump complet d'une carte MIFARE Classic 1K par attaque dictionnaire.
    /// Tente de lire les 16 secteurs (64 blocs) en testant un dictionnaire
    /// de clés communes (KeyA puis KeyB par secteur).
    pub fn mifare_dump(&mut self, uid: &NfcUid) -> anyhow::Result<MifareDump> {
        log::info!("Debut dump MIFARE Classic 1K...");
        let dump = attacks::dump_all_sectors(self, uid);
        let readable = dump.readable.iter().filter(|&&r| r).count();
        log::info!("Dump termine : {}/64 blocs lus", readable);
        Ok(dump)
    }
}

// ── NfcUid ─────────────────────────────────────────────────────────────────

pub struct NfcUid {
    pub bytes: [u8; 7],
    pub len: usize,
}

impl NfcUid {
    pub fn to_hex(&self) -> heapless::String<32> {
        let mut s: heapless::String<32> = heapless::String::new();
        for i in 0..self.len {
            if i > 0 {
                s.push(':').ok();
            }
            let b = self.bytes[i];
            s.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap_or('?')
                    .to_ascii_uppercase(),
            )
            .ok();
            s.push(
                char::from_digit((b & 0xF) as u32, 16)
                    .unwrap_or('?')
                    .to_ascii_uppercase(),
            )
            .ok();
        }
        s
    }
}
