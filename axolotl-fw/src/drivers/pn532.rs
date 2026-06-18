//! Driver PN532 minimal — I2C
//! Protocole I2C PN532 (datasheet section 6.2.4) :
//!   - Trame HSS (host → PN532) : PREAMBLE + START_CODE + LEN + LCS + TFI + DATA + DCS + POSTAMBLE
//!   - Lecture : d'abord lire 1 byte RDY (0x01 = prêt), puis lire la trame réponse

use esp_idf_hal::{delay::FreeRtos, delay::BLOCK, i2c::I2cDriver};

const PN532_ADDR: u8 = 0x24;

// Commandes
const CMD_GET_FIRMWARE_VERSION: u8 = 0x02;
const CMD_SAM_CONFIGURATION: u8 = 0x14;
const CMD_IN_LIST_PASSIVE_TARGET: u8 = 0x4A;

// Trame PN532
const PREAMBLE: u8 = 0x00;
const START1: u8 = 0x00;
const START2: u8 = 0xFF;
const POSTAMBLE: u8 = 0x00;
const TFI_H2C: u8 = 0xD4; // Host → PN532
const TFI_C2H: u8 = 0xD5; // PN532 → Host

pub struct Pn532<'d> {
    i2c: I2cDriver<'d>,
}

impl<'d> Pn532<'d> {
    pub fn new(i2c: I2cDriver<'d>) -> anyhow::Result<Self> {
        let mut pn532 = Self { i2c };
        FreeRtos::delay_ms(500);

        // Wakeup sequence : envoyer 0x55 x16 pour sortir le PN532 du sleep
        let wakeup = [0x55u8; 16];
        let _ = pn532.i2c.write(PN532_ADDR, &wakeup, BLOCK);
        FreeRtos::delay_ms(100);
        // Flush : attendre que le bus soit stable
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
        log::info!("PN532 prêt");
        Ok(pn532)
    }

    /// Construit et envoie une trame PN532 complète avec checksum
    fn send_frame(&mut self, cmd: u8, params: &[u8]) -> anyhow::Result<()> {
        let data_len = 2 + params.len(); // TFI + CMD + params
        let lcs = (!(data_len as u8)).wrapping_add(1); // LCS = ~LEN + 1

        // Checksum données : ~(TFI + CMD + params) + 1
        let mut sum = TFI_H2C.wrapping_add(cmd);
        for &b in params {
            sum = sum.wrapping_add(b);
        }
        let dcs = (!sum).wrapping_add(1);

        // Construire la trame complète
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
            .map_err(|e| anyhow::anyhow!("PN532 write: {:?}", e))?;
        Ok(())
    }

    /// Attend ACK du PN532 (6 bytes : 00 00 FF 00 FF 00)
    fn read_ack(&mut self) -> anyhow::Result<()> {
        self.wait_ready(50)?;
        let mut ack = [0u8; 7]; // RDY + 6 bytes ACK
        self.i2c
            .read(PN532_ADDR, &mut ack, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read ACK: {:?}", e))?;
        // ack[0]=RDY, ack[1..6]=00 00 FF 00 FF 00
        Ok(())
    }

    /// Lit la réponse PN532, retourne les bytes de données (après TFI+CMD)
    fn read_response(&mut self, cmd: u8) -> anyhow::Result<heapless::Vec<u8, 32>> {
        self.wait_ready(100)?;
        let mut buf = [0u8; 32];
        self.i2c
            .read(PN532_ADDR, &mut buf, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read resp: {:?}", e))?;

        // buf[0]=RDY, buf[1]=PREAMBLE, buf[2]=START1, buf[3]=START2
        // buf[4]=LEN, buf[5]=LCS, buf[6]=TFI(D5), buf[7]=CMD+1, buf[8..]=DATA
        if buf[6] != TFI_C2H {
            return Err(anyhow::anyhow!("PN532 TFI inattendu: {:#02x}", buf[6]));
        }
        if buf[7] != cmd + 1 {
            return Err(anyhow::anyhow!("PN532 cmd inattendue: {:#02x}", buf[7]));
        }
        let len = buf[4] as usize;
        let data_start = 8;
        let data_end = data_start + len.saturating_sub(2); // -2 pour TFI+CMD

        let mut result: heapless::Vec<u8, 32> = heapless::Vec::new();
        for i in data_start..data_end.min(32) {
            result.push(buf[i]).ok();
        }
        Ok(result)
    }

    /// Attend que RDY == 0x01, max_tries × 10ms
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

    /// Scan carte ISO14443A — retourne UID si présente
    pub fn read_uid(&mut self) -> anyhow::Result<Option<NfcUid>> {
        self.send_frame(CMD_IN_LIST_PASSIVE_TARGET, &[0x01, 0x00])?;
        self.read_ack()?;

        // Timeout plus court pour le scan (pas d'erreur si pas de carte)
        if self.wait_ready(30).is_err() {
            return Ok(None);
        }

        let mut buf = [0u8; 32];
        self.i2c
            .read(PN532_ADDR, &mut buf, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read UID: {:?}", e))?;

        // buf[8] = NbTg
        if buf[8] == 0 {
            return Ok(None);
        }

        // buf[9]=Tg, buf[10..11]=ATQA, buf[12]=SAK, buf[13]=NIDLen, buf[14..]=UID
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
}

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
