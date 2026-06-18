//! Module NFC — Driver PN532 (I²C) + MIFARE Classic dump
//!
//! Protocole I²C PN532 (AN10609 §6.2.4) :
//!   PREAMBLE + START_CODE + LEN + LCS + TFI + DATA + DCS + POSTAMBLE
//!   Lecture : lire 1 byte RDY (0x01 = prêt) puis lire la trame réponse.

use esp_idf_hal::{delay::FreeRtos, delay::BLOCK, i2c::I2cDriver};

pub mod attacks;
pub mod darkside;
pub mod nested;

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
const CMD_IN_COMMUNICATE_THRU: u8 = 0x42;
const CMD_WRITE_REGISTER: u8 = 0x08;
const CMD_IN_RELEASE: u8 = 0x52;
const CMD_RF_CONFIGURATION: u8 = 0x32;

// Registres CIU (Contactless Interface Unit) du PN532.
// CIU_ManualRCV (0x630D) : bit 4 = ParityDisable
const CIU_MANUAL_RCV_REG: u16 = 0x630D;
// CIU_TxMode (0x6308) : bit 7 = TxCRCEn (1=CIU appende CRC en TX)
#[allow(dead_code)] // réservé attaques bas-niveau (nested/darkside)
const CIU_TX_MODE_REG: u16 = 0x6308;
// CIU_RxMode (0x6309) : bit 7 = RxCRCEn (1=CIU vérifie CRC en RX)
#[allow(dead_code)]
const CIU_RX_MODE_REG: u16 = 0x6309;
#[allow(dead_code)]
const CMD_READ_REGISTER: u8 = 0x06;

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

        // Probe firmware avec retries : au boot, le bus I²C / PN532 peut ne pas
        // être prêt du premier coup (write ESP_FAIL observé). On réessaye tout le
        // handshake (wakeup + flush + GetFirmwareVersion) plutôt que de tuer
        // l'app — avant, un seul échec faisait `return Err` → reboot complet.
        let mut ver = [0u8; 3];
        let mut ok = false;
        for attempt in 0..10 {
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

            match pn532.get_firmware_version() {
                Ok(v) if v[0] != 0 => {
                    ver = v;
                    ok = true;
                    break;
                }
                Ok(_) => log::warn!("PN532 probe {}/10 : reponse vide", attempt + 1),
                Err(e) => log::warn!("PN532 probe {}/10 : {:?}", attempt + 1, e),
            }
            FreeRtos::delay_ms(150);
        }
        if !ok {
            return Err(anyhow::anyhow!("PN532 introuvable apres 10 essais"));
        }
        log::info!(
            "PN532 OK — IC={:#02x} Ver={} Rev={}",
            ver[0],
            ver[1],
            ver[2]
        );

        pn532.sam_configuration()?;
        // MxRtyPassiveActivation=2 : InListPassiveTarget termine en <20ms si
        // aucune carte n'est présente. Sans ça, le PN532 tourne indéfiniment,
        // le wait_ready(30) de read_uid expire, et la prochaine commande I²C
        // arrive pendant que le PN532 est encore occupé → corruption du bus.
        let _ = pn532.send_frame(CMD_RF_CONFIGURATION, &[0x05, 0xFF, 0x01, 0x02]);
        let _ = pn532.read_ack();
        let _ = pn532.read_response(CMD_RF_CONFIGURATION);
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
    // TODO(nfc): si "PN532 timeout" réapparaît, distinguer ici (a) i2c.read Err
    // (NACK bus) vs (b) read OK mais rdy != 0x01 (PN532 jamais prêt) — un log
    // unique transforme le diagnostic en certitude au lieu de tâtonner.
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

    // ── Primitives bas-niveau : InCommunicateThru / CRC-A / nonce brut ───

    /// CRC-A ISO 14443-A (poly 0x1021, init 0x6363).
    #[allow(dead_code)] // utilisé par les attaques bas-niveau (nested/darkside)
    pub fn crc_a(data: &[u8]) -> [u8; 2] {
        let mut crc: u16 = 0x6363;
        for &byte in data {
            let ch = byte ^ (crc as u8);
            let ch = ch ^ (ch << 4);
            crc = (crc >> 8)
                ^ ((ch as u16) << 8)
                ^ ((ch as u16) << 3)
                ^ ((ch as u16) >> 4);
        }
        [(crc & 0xFF) as u8, (crc >> 8) as u8]
    }

    /// Envoie des octets bruts à la cible (InCommunicateThru 0x42).
    /// Le PN532 n'applique pas de couche Crypto1 — les bytes sont relayés tels quels.
    /// Retourne les bytes reçus de la carte (status byte exclu).
    pub fn in_communicate_thru(&mut self, data: &[u8]) -> anyhow::Result<heapless::Vec<u8, 32>> {
        // InCommunicateThru reçoit le data sans Tg (le PN532 l'ajoute lui-même).
        self.send_frame(CMD_IN_COMMUNICATE_THRU, data)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_COMMUNICATE_THRU)?;
        // Premier byte = status : 0x00 = succès, autres = erreur RF.
        if resp.is_empty() {
            return Err(anyhow::anyhow!("InCommunicateThru: réponse vide"));
        }
        let status = resp[0];
        // 0x01 = timeout (carte HALT), on le tolère pour certaines probes.
        if status != 0x00 && status != 0x01 {
            return Err(anyhow::anyhow!("InCommunicateThru status={:#02x}", status));
        }
        let mut result: heapless::Vec<u8, 32> = heapless::Vec::new();
        for &b in resp.iter().skip(1) {
            result.push(b).ok();
        }
        Ok(result)
    }

    /// Variante qui tolère tous les status codes et retourne (status, data).
    /// Nécessaire pour détecter les cartes magic (réponse ACK 4-bit → CRC error).
    fn in_communicate_thru_relaxed(&mut self, data: &[u8]) -> anyhow::Result<(u8, heapless::Vec<u8, 32>)> {
        self.send_frame(CMD_IN_COMMUNICATE_THRU, data)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_IN_COMMUNICATE_THRU)?;
        if resp.is_empty() {
            return Err(anyhow::anyhow!("réponse vide"));
        }
        let status = resp[0];
        let mut result: heapless::Vec<u8, 32> = heapless::Vec::new();
        for &b in resp.iter().skip(1) {
            result.push(b).ok();
        }
        Ok((status, result))
    }

    /// Lit un registre CIU via ReadRegister (cmd 0x06).
    #[allow(dead_code)] // utilisé par les attaques bas-niveau (nested/darkside)
    fn read_register(&mut self, addr: u16) -> u8 {
        let hi = (addr >> 8) as u8;
        let lo = (addr & 0xFF) as u8;
        if self.send_frame(CMD_READ_REGISTER, &[hi, lo]).is_err() {
            return 0;
        }
        if self.read_ack().is_err() {
            return 0;
        }
        match self.read_response(CMD_READ_REGISTER) {
            Ok(r) => r.first().copied().unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Écrit un registre CIU via WriteRegister (cmd 0x08).
    #[allow(dead_code)] // utilisé par les attaques bas-niveau (nested/darkside)
    fn write_register_raw(&mut self, addr: u16, val: u8) {
        let hi = (addr >> 8) as u8;
        let lo = (addr & 0xFF) as u8;
        let _ = self.send_frame(CMD_WRITE_REGISTER, &[hi, lo, val]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_WRITE_REGISTER);
    }

    /// Tente de désactiver la vérification automatique de parité dans le PN532
    /// (registre CIU_ManualRCV, bit4=ParityDisable).
    /// Certains clones IC=0x32 ignorent cette commande — on vérifie en retour.
    /// Retourne `true` si la commande WriteRegister a été acceptée.
    pub fn try_disable_parity(&mut self) -> bool {
        let reg_hi = (CIU_MANUAL_RCV_REG >> 8) as u8;
        let reg_lo = (CIU_MANUAL_RCV_REG & 0xFF) as u8;
        // bit 4 = ParityDisable, bit 5 = TxMix (ne pas toucher) — on met juste bit4.
        let params = [reg_hi, reg_lo, 0x10u8];
        if self.send_frame(CMD_WRITE_REGISTER, &params).is_err() {
            return false;
        }
        if self.read_ack().is_err() {
            return false;
        }
        self.read_response(CMD_WRITE_REGISTER).is_ok()
    }

    /// Capture le nonce brut NT via InCommunicateThru (sans finaliser l'auth).
    ///
    /// Après InListPassiveTarget, le CIU est en mode MIFARE Type A 106kbps :
    /// - TX CRCEn = 1 → le CIU appende automatiquement CRC-A à la commande
    /// - RX CRCEn = 1 → le CIU vérifie et stripe le CRC de la réponse NT
    ///
    /// Il ne faut donc PAS inclure de CRC manuel — sinon double CRC → carte rejette.
    /// La carte répond toujours au challenge NT même si le secteur est verrouillé.
    pub fn read_raw_nonce(&mut self, block: u8) -> anyhow::Result<[u8; 4]> {
        // Commande d'auth sans CRC — le CIU ajoute le CRC automatiquement.
        let frame = [MIFARE_AUTH_A, block];
        let resp = self.in_communicate_thru(&frame)?;
        // Le CIU a stripé le CRC de la réponse → on attend 4 bytes NT en clair.
        if resp.len() < 4 {
            return Err(anyhow::anyhow!("NT trop court ({} bytes)", resp.len()));
        }
        log::info!("NT raw: {:02X} {:02X} {:02X} {:02X}", resp[0], resp[1], resp[2], resp[3]);
        Ok([resp[0], resp[1], resp[2], resp[3]])
    }

    /// Envoie un AR (reader response) bogus après un read_raw_nonce et retourne
    /// le NACK chiffré de la carte (1 byte). Les 4 bits hauts du NACK sont ks4.
    /// NACK valeur attendue = 0x5 (0101) → ks4 = nack_enc XOR 0x5.
    pub fn send_bogus_ar_get_nack(&mut self, bogus_nr: [u8; 4], bogus_ar: [u8; 4]) -> anyhow::Result<u8> {
        // Envoie nr (4 bytes) + ar (4 bytes) en une seule trame.
        let frame = [
            bogus_nr[0], bogus_nr[1], bogus_nr[2], bogus_nr[3],
            bogus_ar[0], bogus_ar[1], bogus_ar[2], bogus_ar[3],
        ];
        let resp = self.in_communicate_thru(&frame)?;
        if resp.is_empty() {
            return Err(anyhow::anyhow!("NACK: réponse vide (timeout ?)"));
        }
        Ok(resp[0])
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
    pub fn re_select(&mut self) -> bool {
        self.rf_cycle();
        for i in 0..10 {
            if matches!(self.read_uid(), Ok(Some(_))) {
                log::debug!("Badge réveillé (tentative {})", i + 1);
                return true;
            }
            FreeRtos::delay_ms(50);
        }
        false
    }

    /// Cycle RF off→on : InRelease (libère la cible + HLTA) puis coupe/rallume le
    /// champ pour power-cycler toute carte présente (HALT/ACTIVE → IDLE), de
    /// nouveau détectable. C'est la SEULE séquence prouvée fiable (re_select la
    /// lance des dizaines de fois par dump sans wedger le bus). Aucune autre
    /// commande (SAMConfiguration, MaxRetries…) ne doit s'ajouter ici : chaque
    /// commande en plus = une occasion de désync du buffer I²C (pas d'IRQ, tout
    /// repose sur le polling RDY).
    fn rf_cycle(&mut self) {
        self.in_release();

        // RF OFF : 100ms suffisent pour vider le condensateur (~50ms typique).
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x01, 0x00]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);

        FreeRtos::delay_ms(100);

        // RF ON
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x01, 0x02]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);

        FreeRtos::delay_ms(60);
    }

    /// Réinitialise le champ RF pour autoriser une NOUVELLE détection.
    ///
    /// Après `read_uid` (InListPassiveTarget → REQA), la carte passe en état
    /// ACTIVE et **ne répond plus à REQA** : impossible de la re-détecter tant
    /// qu'elle reste dans le champ. On power-cycle le champ (cf. [`rf_cycle`])
    /// pour la remettre en IDLE. La boucle de scan re-détecte ensuite.
    ///
    /// Identique au noyau de `re_select` : exactement la séquence prouvée fiable,
    /// rien de plus (pas de SAMConfiguration ni MaxRetries — voir [`recover`]).
    pub fn reset_field(&mut self) {
        self.rf_cycle();
    }

    /// Récupération lourde après une erreur de communication (ex. "PN532
    /// timeout") : draine d'éventuels octets bufferisés (une trame non lue
    /// décale tous les reads suivants), puis ré-applique SAMConfiguration +
    /// MaxRetries.
    ///
    /// À appeler UNIQUEMENT depuis le handler d'erreur du scan. Si ça se
    /// déclenche à chaque scan, c'est que `reset_field` est encore en cause —
    /// c'est le signal, pas une invitation à empiler des commandes ailleurs.
    pub fn recover(&mut self) {
        log::warn!("PN532 recover: re-init apres erreur de comm");
        for _ in 0..6 {
            let mut buf = [0u8; 32];
            let _ = self.i2c.read(PN532_ADDR, &mut buf, BLOCK);
            FreeRtos::delay_ms(5);
        }
        FreeRtos::delay_ms(20);
        let _ = self.sam_configuration();
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x05, 0xFF, 0x01, 0x02]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);
    }

    // ── API publique — restore MIFARE ────────────────────────────────────

    /// Écrit un dump complet sur la carte cible (clone).
    /// - Saute le bloc 0 (UID/fabricant, read-only sur cartes standard).
    /// - Saute les sector trailers (blocs 3, 7, 11, ... 63) pour ne pas
    ///   écraser les clés et access bits de la carte cible.
    /// - `on_sector(sector)` : callback de progression (0..15).
    /// Retourne le nombre de blocs écrits avec succès.
    #[allow(dead_code)] // restore vers carte cible standard — gardé pour usage futur
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

    // ── API publique — clone vers carte magic ─────────────────────────────

    /// Reconstruit le sector trailer pour un clone.
    /// Le dump renvoie KeyA masqué (00) — on réinjecte les vraies clés trouvées.
    /// `reversible=true` : access bits transport FF0780 → la carte clonée reste
    /// réinscriptible (data write A|B, trailer write A) pour re-tester facilement.
    /// `reversible=false` : access bits d'origine (clone 100% fidèle).
    fn reconstruct_trailer(
        sector: u8,
        dump: &MifareDump,
        keys: &[attacks::SectorKey],
        reversible: bool,
    ) -> [u8; 16] {
        let trailer_idx = dump.card_type.sector_trailer(sector).unwrap() as usize;
        let orig = dump.blocks[trailer_idx];
        let find = |ab: u8| {
            keys.iter()
                .find(|k| k.sector == sector && k.key_ab == ab)
                .map(|k| k.key)
        };
        let key_a = find(0).unwrap_or([0xFF; 6]);
        // KeyB : clé trouvée → sinon KeyB lisible du dump (secteurs FF) → sinon KeyA.
        let key_b = find(1).unwrap_or_else(|| {
            let kb: [u8; 6] = orig[10..16].try_into().unwrap_or([0xFF; 6]);
            if kb != [0u8; 6] { kb } else { key_a }
        });
        let (acc, gpb) = if reversible {
            ([0xFFu8, 0x07, 0x80], 0x69u8)
        } else {
            ([orig[6], orig[7], orig[8]], orig[9])
        };
        let mut t = [0u8; 16];
        t[0..6].copy_from_slice(&key_a);
        t[6] = acc[0];
        t[7] = acc[1];
        t[8] = acc[2];
        t[9] = gpb;
        t[10..16].copy_from_slice(&key_b);
        t
    }

    /// Clone un dump vers une carte magic (gen2/CUID — bloc 0 réinscriptible
    /// par commande WRITE normale, sans backdoor).
    ///
    /// - Authentifie la cible avec SA clé courante (FF sur vierge, sinon KeyA
    ///   reconstruite pour re-clone). L'UID change après écriture du bloc 0,
    ///   donc on relit l'UID cible à chaque secteur.
    /// - Écrit tous les blocs en ordre linéaire, **trailer en dernier** par secteur.
    /// - Bloc 0 (UID) inclus : son écriture réussit = carte gen2/CUID confirmée.
    ///
    /// Retourne `(blocs_écrits, bloc0_écrit)`. `bloc0_écrit=false` → carte standard
    /// (bloc 0 verrouillé) : UID non clonable par cette voie.
    pub fn clone_to_magic<F: FnMut(u8, u8)>(
        &mut self,
        dump: &MifareDump,
        keys: &[attacks::SectorKey],
        reversible: bool,
        mut on_sector: F,
    ) -> anyhow::Result<(u32, bool)> {
        let card_type = dump.card_type;
        let total = card_type.sector_count();
        let mut written = 0u32;
        let mut block0_written = false;

        // ── GARDE-FOU : la cible doit être magic (bloc 0 réinscriptible) ───
        // Test NON DESTRUCTIF : auth secteur 0, relire bloc 0, réécrire ses
        // PROPRES octets. Si le WRITE passe → gen2/CUID. On essaye FFFF (carte
        // vierge) PUIS la KeyA reconstruite (re-clone d'une magic déjà clonée).
        //
        // Si le bloc 0 n'est PAS réinscriptible → carte standard/gen1a → on
        // ABANDONNE sans rien écrire : un clone partiel sur carte non-magic
        // réécrit les trailers et BRICK les secteurs (cas vécu sur 8E:0C:19:03).
        let recon0 = Self::reconstruct_trailer(0, dump, keys, reversible);
        let key_a0: [u8; 6] = recon0[0..6].try_into().unwrap();

        self.re_select();
        let mut block0_writable = false;
        match self.read_uid() {
            Ok(Some(u)) => {
                log::info!(
                    "Clone cible UID : {:02X}:{:02X}:{:02X}:{:02X}  SAK={:#04X}",
                    u.bytes[0], u.bytes[1], u.bytes[2], u.bytes[3], u.sak
                );
                let uid4 = [u.bytes[0], u.bytes[1], u.bytes[2], u.bytes[3]];
                for cand in [[0xFFu8; 6], key_a0] {
                    if self.mifare_auth(0, MIFARE_AUTH_A, &cand, &uid4).is_ok() {
                        if let Ok(orig0) = self.mifare_read_block(0) {
                            if self.mifare_write_block(0, &orig0).is_ok() {
                                block0_writable = true;
                                log::info!("Test gen2 : bloc 0 REINSCRIPTIBLE -> gen2/CUID ✓");
                                break;
                            } else {
                                log::info!("Test gen2 : bloc 0 verrouille -> carte standard/gen1a");
                            }
                        }
                    }
                    self.re_select();
                }
                if !block0_writable {
                    log::warn!("Test gen2 : auth/write bloc 0 KO (cible non-magic ou cles inconnues)");
                }
            }
            _ => log::warn!("Clone : aucune carte cible au demarrage"),
        }
        self.re_select();

        // Abandon AVANT toute écriture si la cible n'est pas magic.
        // TODO(nfc): support gen1a — bloc 0 via backdoor 0x40 (7-bit framing),
        // pas par WRITE normal. clone_to_magic gère gen2/CUID uniquement ;
        // router les gen1a vers un clone_gen1a basé sur wipe_gen1a (WIP).
        if !block0_writable {
            log::warn!("Clone ANNULE : cible non-magic (bloc 0 non reinscriptible) — rien ecrit");
            self.reset_field();
            return Err(anyhow::anyhow!("cible non-magic (bloc 0 verrouille)"));
        }

        for sector in 0..total {
            on_sector(sector, total);
            let first = match card_type.sector_first_block(sector) {
                Some(b) => b,
                None => break,
            };
            let bcount = card_type.sector_block_count(sector);
            let trailer = card_type.sector_trailer(sector).unwrap();
            let recon = Self::reconstruct_trailer(sector, dump, keys, reversible);
            let key_a: [u8; 6] = recon[0..6].try_into().unwrap();

            // UID cible courant (change après l'écriture du bloc 0).
            let cur_uid = match self.read_uid() {
                Ok(Some(u)) => u,
                _ => {
                    if !self.re_select() {
                        log::warn!("Clone secteur {:02}: carte perdue — arret", sector);
                        break;
                    }
                    match self.read_uid() {
                        Ok(Some(u)) => u,
                        _ => break,
                    }
                }
            };
            let uid4 = [cur_uid.bytes[0], cur_uid.bytes[1], cur_uid.bytes[2], cur_uid.bytes[3]];

            // Auth cible : FF (vierge) puis KeyA reconstruite (re-clone d'une carte déjà clonée).
            let mut authed = false;
            for cand in [[0xFFu8; 6], key_a] {
                if self.mifare_auth(trailer, MIFARE_AUTH_A, &cand, &uid4).is_ok() {
                    authed = true;
                    break;
                }
                self.re_select();
            }
            if !authed {
                log::warn!("Clone secteur {:02}: auth cible echouee (FF + KeyA)", sector);
                self.re_select();
                continue;
            }

            // Data blocks — tout sauf le trailer ET sauf le bloc 0.
            // Le bloc 0 est écrit EN TOUT DERNIER (il change l'UID, ce qui peut
            // casser la session crypto en cours : on isole ce risque à la fin).
            for i in 0..(bcount - 1) {
                let block = first + i;
                if block == 0 {
                    continue;
                }
                match self.mifare_write_block(block, &dump.blocks[block as usize]) {
                    Ok(_) => written += 1,
                    Err(e) => log::warn!("│ Clone bloc {:03} KO: {:?}", block, e),
                }
            }
            // Trailer EN DERNIER (sinon le secteur bascule en write-KeyB avant les data).
            match self.mifare_write_block(trailer, &recon) {
                Ok(_) => written += 1,
                Err(e) => log::warn!("│ Clone trailer {:03} KO: {:?}", trailer, e),
            }
            self.re_select();
        }

        // ── Bloc 0 (UID) écrit en tout dernier ────────────────────────────
        // Secteur 0 vient d'être cloné → sa KeyA est maintenant 4A63… (FF0780,
        // bloc 0 = data block write A|B). On ré-auth avec cette KeyA et on écrit
        // le bloc 0. Comme plus rien ne suit, un éventuel drop de session post-UID
        // n'impacte aucun autre bloc.
        let recon0 = Self::reconstruct_trailer(0, dump, keys, reversible);
        let key_a0: [u8; 6] = recon0[0..6].try_into().unwrap();
        self.re_select();
        if let Ok(Some(u)) = self.read_uid() {
            let uid4 = [u.bytes[0], u.bytes[1], u.bytes[2], u.bytes[3]];
            let mut authed = false;
            for cand in [key_a0, [0xFFu8; 6]] {
                if self.mifare_auth(0, MIFARE_AUTH_A, &cand, &uid4).is_ok() {
                    authed = true;
                    break;
                }
                self.re_select();
            }
            if authed {
                match self.mifare_write_block(0, &dump.blocks[0]) {
                    Ok(_) => {
                        block0_written = true;
                        written += 1;
                        log::info!("Bloc 0 (UID) ecrit — gen2/CUID confirme");
                    }
                    Err(e) => log::warn!("Bloc 0 refuse: {:?} — carte non gen2/CUID", e),
                }
            } else {
                log::warn!("Bloc 0: auth secteur 0 echouee — UID non ecrit");
            }
        }

        // Read-back : l'ACK d'un WRITE magic ne garantit pas que l'octet a pris.
        // On relit le bloc 0 pour confirmer l'UID réel de la carte clonée.
        self.re_select();
        if let Ok(Some(u)) = self.read_uid() {
            log::info!(
                "Read-back UID carte clonee : {:02X}:{:02X}:{:02X}:{:02X}",
                u.bytes[0], u.bytes[1], u.bytes[2], u.bytes[3]
            );
        }

        log::info!(
            "Clone magic termine : {} blocs ecrits, bloc0={}",
            written,
            block0_written
        );
        self.reset_field();
        Ok((written, block0_written))
    }

    // ── API publique — dump MIFARE ────────────────────────────────────────

    /// Dump complet d'une carte MIFARE Classic par attaque dictionnaire.
    /// Détecte 1K/4K via SAK ; on_sector(n) appelé au début de chaque secteur.
    /// Retourne le dump + la liste des clés trouvées (secteur, KeyA/B, valeur).
    pub fn mifare_dump<F: FnMut(u8, u8)>(
        &mut self,
        uid: &NfcUid,
        on_sector: F,
    ) -> anyhow::Result<(Box<MifareDump>, Vec<attacks::SectorKey>)> {
        log::info!("Debut dump MIFARE Classic ({})...", uid.card_type());
        let (dump, keys) = attacks::dump_all_sectors(self, uid, on_sector);
        log::info!(
            "Dump termine : {}/{} blocs lus, {} cles trouvees",
            dump.readable_count(),
            dump.total_blocks(),
            keys.len()
        );
        Ok((dump, keys))
    }

    /// Tente de détecter une carte gen1a ("magic backdoor").
    ///
    /// Envoie 0x40 en byte complet (pas de manipulation CIU_BitFraming — le registre
    /// 0x6306 reste à 0 pour éviter de casser les transmissions suivantes).
    /// Les cartes gen1a répondent ACK=0x0A ; les vraies NXP et gen2 ignorent (timeout).
    ///
    /// Après la probe, fait un RF cycle + SAMConfiguration pour garantir un état PN532
    /// propre — sans ça, l'InCommunicateThru laisse le PN532 dans un état qui empêche
    /// les InAuthenticate suivantes (auth FFFFFFFFFFFF échoue même sur carte vierge).
    pub fn detect_magic_gen1a(&mut self) -> bool {
        let result = self.in_communicate_thru_relaxed(&[0x40]);

        let is_magic = match result {
            Ok((status, ref resp)) => {
                (status == 0x00 || status == 0x02) && resp.first() == Some(&0x0A)
            }
            Err(_) => false,
        };

        if is_magic {
            log::info!("MAGIC GEN1A detectee — carte UID-modifiable");
            let _ = self.in_communicate_thru_relaxed(&[0x43]);
        }

        // Reset PN532 : RF cycle + SAMConfig pour revenir à un état propre.
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x01, 0x00]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);
        FreeRtos::delay_ms(120);
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x01, 0x02]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);
        FreeRtos::delay_ms(80);
        let _ = self.sam_configuration();
        FreeRtos::delay_ms(50);

        // Re-sélectionne la carte pour les opérations suivantes.
        for _ in 0..10 {
            if matches!(self.read_uid(), Ok(Some(_))) {
                return is_magic;
            }
            FreeRtos::delay_ms(50);
        }
        is_magic
    }

    /// Wipe gen1a : efface tous les blocs via le backdoor 0x40 sans auth.
    ///
    /// Séquence : 0x40 → ACK 0x0A, 0x43 → ACK 0x0A, puis WRITE (0xA0)
    /// bloc par bloc via InCommunicateThru (CRC-A appended par le CIU).
    /// Trailers → transport state : `FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF`
    /// Blocs data → 16 zéros (sauf bloc 0 conservé tel quel pour ne pas bricker l'UID).
    ///
    /// Retourne (blocs_effacés, blocs_total).
    pub fn wipe_gen1a<F: FnMut(u8, u8)>(&mut self, mut on_block: F) -> (u8, u8) {
        // Ouvre le backdoor
        let unlock1 = self.in_communicate_thru_relaxed(&[0x40]);
        let ok1 = matches!(unlock1, Ok((_, ref d)) if d.first() == Some(&0x0A));
        if !ok1 {
            log::warn!("wipe_gen1a: 0x40 ACK manquant, abandon");
            self.reset_field();
            return (0, 63);
        }
        let unlock2 = self.in_communicate_thru_relaxed(&[0x43]);
        let ok2 = matches!(unlock2, Ok((_, ref d)) if d.first() == Some(&0x0A));
        if !ok2 {
            log::warn!("wipe_gen1a: 0x43 ACK manquant, abandon");
            self.reset_field();
            return (0, 63);
        }
        log::info!("wipe_gen1a: backdoor ouvert");

        const TRANSPORT_TRAILER: [u8; 16] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // KeyA
            0xFF, 0x07, 0x80, 0x69,             // Access bits transport
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // KeyB
        ];
        const ZERO_BLOCK: [u8; 16] = [0u8; 16];

        let mut written = 0u8;
        // Blocs 1..63 (bloc 0 = UID, on ne touche pas)
        for blk in 1u8..64 {
            let is_trailer = (blk % 4) == 3;
            let data = if is_trailer { &TRANSPORT_TRAILER } else { &ZERO_BLOCK };

            // WRITE : 0xA0 + bloc, puis 16 bytes data
            // Le CIU ajoute CRC-A automatiquement sur chaque trame.
            let cmd_write = [0xA0u8, blk];
            let ack1 = self.in_communicate_thru_relaxed(&cmd_write);
            let step1_ok = matches!(ack1, Ok((_, ref d)) if d.first() == Some(&0x0A));
            if !step1_ok {
                log::warn!("wipe blk{}: WRITE cmd ACK raté", blk);
                on_block(blk, 0xFF);
                continue;
            }
            let ack2 = self.in_communicate_thru_relaxed(data);
            let step2_ok = matches!(ack2, Ok((_, ref d)) if d.first() == Some(&0x0A));
            if step2_ok {
                written += 1;
                log::info!("wipe blk{}: OK", blk);
                on_block(blk, 0x00);
            } else {
                log::warn!("wipe blk{}: data ACK raté", blk);
                on_block(blk, 0xFF);
            }
        }

        // Reset PN532 propre après backdoor
        self.reset_field();
        log::info!("wipe_gen1a: {}/63 blocs effacés", written);
        (written, 63)
    }

    // ── API publique — Ultralight / NTAG ─────────────────────────────────

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

    // ── API publique — Attaques cryptographiques MIFARE ───────────────────

    /// Probe Darkside : collecte des nonces bruts, détecte le type de PRNG.
    /// Résultat loggé en détail dans le moniteur.
    pub fn darkside_probe(&mut self, uid: &NfcUid) -> darkside::DarksideProbe {
        darkside::probe(self, uid)
    }

    /// Attaque Darkside complète. Ne fonctionne que si probe_prng() retourne PrngType::Fixed.
    /// `on_progress(attempt, total)` : callback de progression.
    pub fn darkside_attack<F: FnMut(u32, u32)>(
        &mut self,
        uid: &NfcUid,
        fixed_nt: u32,
        on_progress: F,
    ) -> Option<[u8; 6]> {
        darkside::run_attack(self, uid, fixed_nt, on_progress)
    }

    /// Collecte de nonces nichés pour l'attaque Nested (style MFOC).
    /// Nécessite une clé connue pour au moins un secteur.
    pub fn nested_collect(
        &mut self,
        uid: &NfcUid,
        known_sector: u8,
        known_key: [u8; 6],
        target_sector: u8,
        samples: u8,
    ) -> nested::NestedResult {
        nested::collect_nested_nonces(self, uid, known_sector, known_key, target_sector, samples)
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
