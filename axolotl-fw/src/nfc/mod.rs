//! Module NFC — Driver PN532 (I²C) + MIFARE Classic dump.
//! Trame I²C PN532 (AN10609 §6.2.4) : PREAMBLE + START + LEN + LCS + TFI + DATA
//! + DCS + POSTAMBLE ; lecture précédée d'un byte RDY (0x01 = prêt).

use esp_idf_hal::{
    delay::{FreeRtos, BLOCK},
    gpio::{Output, PinDriver},
    i2c::I2cDriver,
};

pub mod attacks;

// Re-exports depuis axolotl-core pour que main.rs puisse écrire `nfc::NfcUid`
// sans changer ses imports actuels.
pub use axolotl_core::{card::NfcUid, dump::MifareDump, layout::ClassicType};

use axolotl_core::protocol::{
    MIFARE_AUTH_A, MIFARE_AUTH_B, MIFARE_READ, MIFARE_UL_WRITE, MIFARE_WRITE,
};

/// Trailer « transport state » NXP : KeyA=FF…, access bits d'usine (FF 07 80 69),
/// KeyB=FF…. Valeur sûre — NE JAMAIS recalculer les access bits à la main : un
/// octet faux brique définitivement le secteur. Partagé wipe_gen1a / wipe_to_blank.
const TRANSPORT_TRAILER: [u8; 16] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // KeyA
    0xFF, 0x07, 0x80, 0x69, // Access bits transport
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // KeyB
];
const ZERO_BLOCK: [u8; 16] = [0u8; 16];

// ── Adresse I²C ────────────────────────────────────────────────────────────
const PN532_ADDR: u8 = 0x24;

// ── Commandes PN532 ────────────────────────────────────────────────────────
const CMD_GET_FIRMWARE_VERSION: u8 = 0x02;
const CMD_SAM_CONFIGURATION: u8 = 0x14;
const CMD_IN_LIST_PASSIVE_TARGET: u8 = 0x4A;
const CMD_IN_DATA_EXCHANGE: u8 = 0x40;
const CMD_IN_COMMUNICATE_THRU: u8 = 0x42;
const CMD_IN_RELEASE: u8 = 0x52;
const CMD_RF_CONFIGURATION: u8 = 0x32;
const CMD_TG_INIT_AS_TARGET: u8 = 0x8C;
const CMD_TG_GET_DATA: u8 = 0x86;
const CMD_TG_SET_DATA: u8 = 0x8E;
const CMD_WRITE_REGISTER: u8 = 0x08;

// Registres CIU (PN53x, adresses libnfc pn53x-internal.h) : pilotent CRC et
// bit-framing pour la backdoor gen1a — le réveil 0x40 doit partir en trame
// 7 bits, CRC OFF, sinon la carte l'ignore (faux « non-magic »).
const REG_CIU_TX_MODE: u16 = 0x6302; // bit7 = TxCRCEn
const REG_CIU_RX_MODE: u16 = 0x6303; // bit7 = RxCRCEn
const REG_CIU_BIT_FRAMING: u16 = 0x633D; // bits[2:0] = TxLastBits

// Cartes gen1a bas coût : l'écriture (et parfois le réveil) n'ACK souvent qu'au
// 2e/3e essai. Le fournisseur T4U le documente lui-même (« ce message d'erreur
// est normal, recommencez jusqu'à réussite »). On retente donc en boucle.
const GEN1A_UNLOCK_TRIES: u8 = 4;
const GEN1A_WRITE_TRIES: u8 = 4;

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
        // Pas d'IRQ : la broche gpio1 était le SEUL écart matériel avec la
        // branche rfid_attacks (qui marchait) et déréglait la comm I²C du PN532
        // (write ESP_ERR_TIMEOUT/ESP_FAIL). On revient au polling RDY sur le bus.
        let mut pn532 = Self { i2c };
        FreeRtos::delay_ms(500);

        // Probe firmware avec retries : au boot le PN532 n'est pas prêt du premier
        // coup. On rejoue tout le handshake plutôt que de faire échouer l'app.
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
        // MxRtyPassiveActivation=2 : InListPassiveTarget rend la main en <20 ms
        // sans carte, sinon il boucle et la commande I²C suivante corrompt le bus.
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
    // TODO(nfc): en cas de "PN532 timeout", distinguer NACK bus (i2c.read Err) de
    // rdy != 0x01 (PN532 jamais prêt) via un log dédié.
    fn wait_ready(&mut self, max_tries: u32) -> anyhow::Result<()> {
        // Polling de l'octet RDY sur l'I²C (comportement rfid_attacks, fiable).
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

    // ── Primitive bas-niveau : InCommunicateThru (relayé sans couche Crypto1) ──
    // Utilisée par le clone / wipe gen1a pour dialoguer avec la backdoor magic.

    /// Variante qui tolère tous les status codes et retourne (status, data).
    /// Nécessaire pour détecter les cartes magic (réponse ACK 4-bit → CRC error).
    fn in_communicate_thru_relaxed(
        &mut self,
        data: &[u8],
    ) -> anyhow::Result<(u8, heapless::Vec<u8, 32>)> {
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

    // ── Pilotage CIU bas niveau (CRC / bit-framing) pour backdoor gen1a ────

    /// PN532 WriteRegister (UM0701-02 §7.2.7) — écrit des paires (adresse,
    /// valeur) dans l'espace registre du CIU. Seule voie pour émettre la trame
    /// courte 7 bits exigée par le réveil 0x40 d'une carte magic gen1a.
    fn write_register(&mut self, regs: &[(u16, u8)]) -> anyhow::Result<()> {
        let mut params: heapless::Vec<u8, 48> = heapless::Vec::new();
        for &(addr, val) in regs {
            params.push((addr >> 8) as u8).ok();
            params.push((addr & 0xFF) as u8).ok();
            params.push(val).ok();
        }
        self.send_frame(CMD_WRITE_REGISTER, &params)?;
        self.read_ack()?;
        self.read_response(CMD_WRITE_REGISTER)?;
        Ok(())
    }

    /// Active/coupe le CRC TX+RX du CIU. OFF pour la backdoor gen1a (0x40/0x43),
    /// ON pour les commandes MIFARE normales. Le prochain InListPassiveTarget
    /// reconfigure de toute façon ces registres.
    fn set_crc(&mut self, on: bool) {
        let v = if on { 0x80 } else { 0x00 };
        if let Err(e) = self.write_register(&[(REG_CIU_TX_MODE, v), (REG_CIU_RX_MODE, v)]) {
            log::warn!("set_crc({}): WriteRegister KO: {:?}", on, e);
        }
    }

    /// Règle TxLastBits : 7 pour la trame courte du réveil gen1a (0x40), 0 =
    /// octet complet (cas par défaut).
    fn set_tx_last_bits(&mut self, bits: u8) {
        if let Err(e) = self.write_register(&[(REG_CIU_BIT_FRAMING, bits & 0x07)]) {
            log::warn!("set_tx_last_bits({}): WriteRegister KO: {:?}", bits, e);
        }
    }

    /// Ouvre la backdoor gen1a (libnfc `unlock_card`) : HALT → 0x40 (trame 7 bits,
    /// CRC OFF) → 0x43 (octet plein, CRC OFF), ACK 0x0A attendu. Laisse le CIU
    /// CRC ON en sortie. Carte déjà sélectionnée. Réessaie `GEN1A_UNLOCK_TRIES` fois.
    fn gen1a_unlock(&mut self) -> bool {
        for attempt in 1..=GEN1A_UNLOCK_TRIES {
            // HALT avec CRC : place la carte en état HALT, où le réveil l'attend.
            self.set_crc(true);
            self.set_tx_last_bits(0);
            let _ = self.in_communicate_thru_relaxed(&[0x50, 0x00]); // pas de réponse

            // Réveil 0x40 : trame courte 7 bits, CRC coupé.
            self.set_crc(false);
            self.set_tx_last_bits(7);
            let r40 = self.in_communicate_thru_relaxed(&[0x40]);
            self.set_tx_last_bits(0);
            let ok40 = matches!(r40, Ok((_, ref d)) if d.first() == Some(&0x0A));
            log::info!(
                "gen1a unlock {}/{} : 0x40 -> {:?}",
                attempt,
                GEN1A_UNLOCK_TRIES,
                r40
            );
            if !ok40 {
                self.set_crc(true);
                self.re_select();
                continue;
            }

            // 0x43 : octet plein, CRC toujours coupé.
            let r43 = self.in_communicate_thru_relaxed(&[0x43]);
            let ok43 = matches!(r43, Ok((_, ref d)) if d.first() == Some(&0x0A));
            log::info!(
                "gen1a unlock {}/{} : 0x43 -> {:?}",
                attempt,
                GEN1A_UNLOCK_TRIES,
                r43
            );
            self.set_crc(true); // restaure CRC pour la phase WRITE 0xA0
            if ok43 {
                log::info!("gen1a backdoor ouverte (essai {})", attempt);
                return true;
            }
            self.re_select();
        }
        false
    }

    /// Écrit un bloc via la backdoor gen1a **déjà ouverte** (WRITE 0xA0 + 16
    /// octets, CRC ON ajouté par le CIU). Réessaie `GEN1A_WRITE_TRIES` fois : ces
    /// cartes ACK souvent au 2e/3e essai seulement.
    fn gen1a_write_block(&mut self, blk: u8, data: &[u8; 16]) -> bool {
        for _ in 0..GEN1A_WRITE_TRIES {
            let a1 = self.in_communicate_thru_relaxed(&[0xA0, blk]);
            if !matches!(a1, Ok((_, ref d)) if d.first() == Some(&0x0A)) {
                continue;
            }
            let a2 = self.in_communicate_thru_relaxed(data);
            if matches!(a2, Ok((_, ref d)) if d.first() == Some(&0x0A)) {
                return true;
            }
        }
        false
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

    /// Re-sélectionne la carte après un auth raté. `InRelease` la met en HALT (où
    /// REQA est ignoré) : un cycle RF off→on la ramène en IDLE pour qu'elle
    /// réponde de nouveau à InListPassiveTarget.
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

    /// Cycle RF off→on : InRelease puis coupe/rallume le champ pour power-cycler
    /// la carte (HALT/ACTIVE → IDLE). Ne rien ajouter ici : toute commande en plus
    /// risque de désync le buffer I²C (polling RDY, pas d'IRQ).
    fn rf_cycle(&mut self) {
        self.in_release();

        // RF OFF : 100ms suffisent pour vider le condensateur (~50ms typique).
        let params = [0x01u8, 0x00u8];
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &params);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);

        FreeRtos::delay_ms(100);

        // RF ON
        let params = [0x01u8, 0x02u8];
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &params);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);

        FreeRtos::delay_ms(60);
    }

    /// Réinitialise le champ RF pour autoriser une nouvelle détection : après
    /// `read_uid`, la carte reste ACTIVE et ignore REQA ; un power-cycle du champ
    /// (cf. [`rf_cycle`]) la remet en IDLE.
    pub fn reset_field(&mut self) {
        self.rf_cycle();
    }

    /// Récupération lourde après une erreur de comm ("PN532 timeout") : draine le
    /// buffer I²C (une trame non lue décale les reads suivants) puis ré-applique
    /// SAMConfiguration + MaxRetries. À n'appeler que depuis le handler d'erreur.
    pub fn recover(&mut self) {
        log::warn!("PN532 recover: re-init apres erreur de comm");
        // Vide le bus I²C de tout octet bloqué.
        for _ in 0..10 {
            let mut buf = [0u8; 32];
            let _ = self.i2c.read(PN532_ADDR, &mut buf, BLOCK);
            FreeRtos::delay_ms(10);
        }

        self.rf_cycle();

        let _ = self.sam_configuration();
        let _ = self.send_frame(CMD_RF_CONFIGURATION, &[0x05, 0xFF, 0x01, 0x02]);
        let _ = self.read_ack();
        let _ = self.read_response(CMD_RF_CONFIGURATION);
    }

    // ── API publique — clone vers carte magic ─────────────────────────────

    /// Reconstruit le sector trailer d'un clone en réinjectant les vraies clés
    /// (le dump renvoie KeyA masqué). `reversible` : access bits transport FF0780
    /// (carte re-inscriptible) sinon access bits d'origine (clone fidèle).
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
            if kb != [0u8; 6] {
                kb
            } else {
                key_a
            }
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

    /// Clone un dump vers une carte magic gen2/CUID (bloc 0 réinscriptible par
    /// WRITE normal) ; trailer écrit en dernier par secteur. Retourne
    /// `(blocs_écrits, bloc0_écrit)` — `bloc0_écrit=false` = UID non clonable.
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

        // Garde-fou : test non destructif que le bloc 0 est réinscriptible (auth
        // secteur 0, relire/réécrire ses propres octets, clés FFFF puis KeyA). Si
        // non → on abandonne sans rien écrire (un clone partiel brique la carte).
        let recon0 = Self::reconstruct_trailer(0, dump, keys, reversible);
        let key_a0: [u8; 6] = recon0[0..6].try_into().unwrap();

        self.re_select();
        let mut block0_writable = false;
        match self.read_uid() {
            Ok(Some(u)) => {
                log::info!(
                    "Clone cible UID : {:02X}:{:02X}:{:02X}:{:02X}  SAK={:#04X}",
                    u.bytes[0],
                    u.bytes[1],
                    u.bytes[2],
                    u.bytes[3],
                    u.sak
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
                    log::warn!(
                        "Test gen2 : auth/write bloc 0 KO (cible non-magic ou cles inconnues)"
                    );
                }
            }
            _ => log::warn!("Clone : aucune carte cible au demarrage"),
        }
        self.re_select();

        if !block0_writable {
            // Fallback gen1a : ouvre la backdoor (HALT → 0x40 7-bit CRC-off →
            // 0x43). Après le re_select précédent la carte est sélectionnée.
            log::info!("Clone gen2 KO — tentative backdoor gen1a");
            if self.gen1a_unlock() {
                log::info!("Clone : backdoor gen1a ouverte — clone en cours");
                return self.clone_gen1a_unlocked(dump, keys, reversible, on_sector);
            }
            log::warn!("Clone ANNULE : cible non-magic (ni gen2 ni gen1a) — rien ecrit");
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
            let uid4 = [
                cur_uid.bytes[0],
                cur_uid.bytes[1],
                cur_uid.bytes[2],
                cur_uid.bytes[3],
            ];

            // Auth cible : FF (vierge) puis KeyA reconstruite (re-clone d'une carte déjà clonée).
            let mut authed = false;
            for cand in [[0xFFu8; 6], key_a] {
                if self
                    .mifare_auth(trailer, MIFARE_AUTH_A, &cand, &uid4)
                    .is_ok()
                {
                    authed = true;
                    break;
                }
                self.re_select();
            }
            if !authed {
                log::warn!(
                    "Clone secteur {:02}: auth cible echouee (FF + KeyA)",
                    sector
                );
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

        // Bloc 0 (UID) écrit en dernier : le secteur 0 vient d'être cloné, on
        // ré-authentifie avec sa nouvelle KeyA (FF0780) pour écrire le bloc 0.
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
                u.bytes[0],
                u.bytes[1],
                u.bytes[2],
                u.bytes[3]
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

    /// Wipe gen1a : ouvre la backdoor ([`Self::gen1a_unlock`]) puis WRITE 0xA0
    /// bloc par bloc — trailers en transport state, data à zéro (bloc 0 conservé
    /// pour ne pas bricker l'UID). Retourne (blocs_effacés, blocs_total).
    pub fn wipe_gen1a<F: FnMut(u8, u8)>(&mut self, mut on_block: F) -> (u8, u8) {
        if !self.gen1a_unlock() {
            log::warn!("wipe_gen1a: backdoor gen1a indisponible (0x40/0x43 sans ACK), abandon");
            self.reset_field();
            return (0, 63);
        }
        log::info!("wipe_gen1a: backdoor ouvert");

        let mut written = 0u8;
        // Blocs 1..63 (bloc 0 = UID, on ne touche pas)
        for blk in 1u8..64 {
            let is_trailer = (blk % 4) == 3;
            let data = if is_trailer {
                &TRANSPORT_TRAILER
            } else {
                &ZERO_BLOCK
            };

            // WRITE 0xA0 + 16 octets, avec retries (CRC-A ajouté par le CIU).
            if self.gen1a_write_block(blk, data) {
                written += 1;
                log::info!("wipe blk{}: OK", blk);
                on_block(blk, 0x00);
            } else {
                log::warn!("wipe blk{}: ecriture KO apres {} essais", blk, GEN1A_WRITE_TRIES);
                on_block(blk, 0xFF);
            }
        }

        // Reset PN532 propre après backdoor
        self.reset_field();
        log::info!("wipe_gen1a: {}/63 blocs effacés", written);
        (written, 63)
    }

    /// Remet une carte magic à blanc (transport state NXP), bloc 0 conservé.
    /// gen1a via backdoor sans auth, gen2/CUID par auth+WRITE (clés FF/00, puis
    /// `last_keys`, puis dict). Retourne (blocs_effacés, total), bloc 0 exclu.
    pub fn wipe_to_blank<F: FnMut(u8, u8)>(
        &mut self,
        last_keys: &[attacks::SectorKey],
        mut on_block: F,
    ) -> (u8, u8) {
        // 1) gen1a : tente le backdoor d'abord. Sur une carte non-gen1a, wipe_gen1a
        //    abandonne proprement (reset_field) et renvoie (0, _) sans rien casser.
        let (g1, t1) = self.wipe_gen1a(&mut on_block);
        if g1 > 0 {
            return (g1, t1);
        }

        // 2) gen2/CUID : auth + write secteur par secteur.
        self.reset_field();
        if !self.re_select() {
            log::warn!("wipe_to_blank: carte absente (gen2)");
            return (0, 0);
        }
        let uid = match self.read_uid() {
            Ok(Some(u)) => u,
            _ => {
                log::warn!("wipe_to_blank: read_uid KO (gen2)");
                return (0, 0);
            }
        };
        let uid4 = [uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]];
        let card_type = ClassicType::from_sak(uid.sak).unwrap_or(ClassicType::Classic1K);
        let total_sectors = card_type.sector_count();
        log::info!("wipe_to_blank: gen2/CUID — {} secteurs", total_sectors);

        let mut written = 0u8;
        let mut total = 0u8;
        for sector in 0..total_sectors {
            let first = match card_type.sector_first_block(sector) {
                Some(b) => b,
                None => break,
            };
            let trailer = match card_type.sector_trailer(sector) {
                Some(t) => t,
                None => break,
            };
            // Clé valide réutilisée d'un bloc à l'autre du secteur (évite de re-balayer
            // tout le dico pour chaque bloc une fois la bonne clé trouvée).
            let mut working: Option<(u8, [u8; 6])> = None;

            // Data blocks d'abord, trailer EN DERNIER : écrire le trailer rebascule
            // les clés du secteur en transport (FF) → tout data écrit après aurait
            // besoin d'une ré-auth FF (même logique que clone_to_magic).
            for blk in first..trailer {
                if blk == 0 {
                    continue; // bloc 0 (UID) conservé — anti-brick
                }
                total += 1;
                if self.wipe_block_any_key(blk, &ZERO_BLOCK, &uid4, sector, last_keys, &mut working)
                {
                    written += 1;
                    on_block(blk, 0x00);
                } else {
                    log::warn!("wipe gen2 blk{}: aucune cle valide en ecriture", blk);
                    on_block(blk, 0xFF);
                }
            }
            // Trailer → transport state, en dernier. NAK ici = secteur PAS vierge
            // (garde ses anciennes clés) → compté comme échec.
            total += 1;
            if self.wipe_block_any_key(
                trailer,
                &TRANSPORT_TRAILER,
                &uid4,
                sector,
                last_keys,
                &mut working,
            ) {
                written += 1;
                on_block(trailer, 0x00);
            } else {
                log::warn!("wipe gen2 trailer{}: NAK — secteur garde ses cles", trailer);
                on_block(trailer, 0xFF);
            }
        }

        self.reset_field();
        log::info!("wipe_to_blank gen2: {}/{} blocs effaces", written, total);
        (written, total)
    }

    /// Écrit `data` dans `block` en cherchant une clé qui authentifie et autorise
    /// l'écriture (`working`, puis FF/00, `last_keys`, dict ; KeyA puis KeyB).
    /// Renvoie `true` dès que le WRITE est ACK.
    fn wipe_block_any_key(
        &mut self,
        block: u8,
        data: &[u8; 16],
        uid4: &[u8; 4],
        sector: u8,
        last_keys: &[attacks::SectorKey],
        working: &mut Option<(u8, [u8; 6])>,
    ) -> bool {
        // 1) clé déjà validée pour ce secteur
        if let Some((ab, k)) = *working {
            if self.try_auth_write(block, data, uid4, ab, &k) {
                return true;
            }
        }
        // 2) FF / 00 (carte vierge ou transport), KeyA puis KeyB
        for k in [[0xFFu8; 6], [0x00u8; 6]] {
            for ab in 0u8..2 {
                if self.try_auth_write(block, data, uid4, ab, &k) {
                    *working = Some((ab, k));
                    return true;
                }
            }
        }
        // 3) clés du dernier dump pour ce secteur
        for sk in last_keys.iter().filter(|s| s.sector == sector) {
            if self.try_auth_write(block, data, uid4, sk.key_ab, &sk.key) {
                *working = Some((sk.key_ab, sk.key));
                return true;
            }
        }
        // 4) dictionnaire complet, KeyA puis KeyB (dernier recours)
        for k in axolotl_core::keys::DEFAULT_KEYS {
            for ab in 0u8..2 {
                if self.try_auth_write(block, data, uid4, ab, k) {
                    *working = Some((ab, *k));
                    return true;
                }
            }
        }
        false
    }

    /// Une tentative atomique : `re_select` (récupère un éventuel HALT) → auth
    /// (KeyA si `key_ab`=0, KeyB sinon) → write. `true` seulement si le WRITE est ACK.
    fn try_auth_write(
        &mut self,
        block: u8,
        data: &[u8; 16],
        uid4: &[u8; 4],
        key_ab: u8,
        key: &[u8; 6],
    ) -> bool {
        if !self.re_select() {
            return false;
        }
        let cmd = if key_ab == 0 {
            MIFARE_AUTH_A
        } else {
            MIFARE_AUTH_B
        };
        if self.mifare_auth(block, cmd, key, uid4).is_err() {
            return false;
        }
        self.mifare_write_block(block, data).is_ok()
    }

    /// Clone un dump vers une carte gen1a, backdoor déjà ouverte par
    /// [`Self::gen1a_unlock`]. Le backdoor bypass l'auth MIFARE : tous les blocs
    /// (bloc 0 / UID inclus) sont écrits directement via WRITE (0xA0).
    fn clone_gen1a_unlocked<F: FnMut(u8, u8)>(
        &mut self,
        dump: &MifareDump,
        keys: &[attacks::SectorKey],
        reversible: bool,
        mut on_sector: F,
    ) -> anyhow::Result<(u32, bool)> {
        log::info!(
            "clone_gen1a: backdoor ouverte — {} blocs a ecrire",
            dump.card_type.block_count()
        );

        let total_blocks = dump.card_type.block_count() as u8;
        let total_sectors = dump.card_type.sector_count();
        let mut written = 0u32;
        let mut block0_written = false;
        let mut last_sector_notified = u8::MAX;

        for blk in 0u8..total_blocks {
            let sector = block_to_sector(dump.card_type, blk);
            if sector != last_sector_notified {
                on_sector(sector, total_sectors);
                last_sector_notified = sector;
            }

            let data: [u8; 16] = if dump.card_type.is_trailer(blk as usize) {
                Self::reconstruct_trailer(sector, dump, keys, reversible)
            } else {
                dump.blocks[blk as usize]
            };

            // WRITE 0xA0 + 16 octets, avec retries (CRC-A ajouté par le CIU).
            if self.gen1a_write_block(blk, &data) {
                written += 1;
                if blk == 0 {
                    block0_written = true;
                }
            } else {
                log::warn!(
                    "clone_gen1a blk{:03}: ecriture KO apres {} essais",
                    blk,
                    GEN1A_WRITE_TRIES
                );
            }
        }

        self.reset_field();
        FreeRtos::delay_ms(100);
        if let Ok(Some(u)) = self.read_uid() {
            log::info!(
                "clone_gen1a read-back UID: {:02X}:{:02X}:{:02X}:{:02X}",
                u.bytes[0],
                u.bytes[1],
                u.bytes[2],
                u.bytes[3]
            );
        }
        log::info!(
            "clone_gen1a: {}/{} blocs ecrits, bloc0={}",
            written,
            total_blocks,
            block0_written
        );
        Ok((written, block0_written))
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

    /// Détecte la taille d'une carte NTAG via le Capability Container (page 3,
    /// byte 2 : 0x12=213, 0x3E=215, 0x6F=216). Retourne le nombre de pages
    /// lisibles ; Ultralight classique → 16 pages par défaut.
    pub fn ntag_detect_pages(&mut self) -> anyhow::Result<u8> {
        let page3 = self.ultralight_read_page(3)?;
        // CC = [magic, version, size, access] ; size → pages totales :
        // 0x12 NTAG213=45, 0x3E NTAG215=135, 0x6F NTAG216=231.
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

    /// Écrit un dump Ultralight/NTAG sur la carte courante (saute les pages 0..3 :
    /// UID + lock + CC). `on_page(page, total)` = progression ; retourne le nombre
    /// de pages écrites.
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

// ── Émulation badge MIFARE Classic ────────────────────────────────────────

/// Résultat de la session d'émulation.
pub enum EmulResult {
    /// Session terminée proprement (lecteur s'est déconnecté).
    Done,
    /// Timeout : aucun lecteur détecté pendant la fenêtre d'attente.
    Timeout,
    /// Erreur matérielle PN532.
    Error(String),
}

impl<'d> Pn532<'d> {
    /// Configure le PN532 en cible passive 106 kbps ISO14443-A (répond seul aux
    /// REQA/WUPA + anticollision ; commandes ensuite via `tg_get_data`).
    /// ATQA/SAK : 1K = [04 00]/0x08, 4K = [02 00]/0x18.
    pub fn tg_init_as_target(
        &mut self,
        uid4: &[u8; 4],
        sak: u8,
        atqa: [u8; 2],
    ) -> anyhow::Result<()> {
        // TgInitAsTarget : mode=0x00 (passif), MifareParams, FelicaParams (zeros), Nfcid3t (zeros)
        let mut params: heapless::Vec<u8, 48> = heapless::Vec::new();
        params.push(0x00).ok(); // Mode: passif
        params.push(atqa[0]).ok(); // ATQA byte 0
        params.push(atqa[1]).ok(); // ATQA byte 1
        params.push(sak).ok(); // SAK
        params.push(4u8).ok(); // NFCIDLength = 4 bytes
        params.push(uid4[0]).ok();
        params.push(uid4[1]).ok();
        params.push(uid4[2]).ok();
        params.push(uid4[3]).ok();
        // FelicaParams (18 bytes, non utilisés) + Nfcid3t (10 bytes)
        for _ in 0..28 {
            params.push(0x00).ok();
        }
        self.send_frame(CMD_TG_INIT_AS_TARGET, &params)?;
        self.read_ack()?;
        // ~10 s d'attente : TgInitAsTarget ne répond que lorsqu'un lecteur active
        // la cible. Laisse le temps d'approcher l'appareil du lecteur de porte.
        let resp = self.read_response_target(CMD_TG_INIT_AS_TARGET, 1000)?;
        if resp.is_empty() {
            return Err(anyhow::anyhow!("TgInitAsTarget: echec"));
        }
        Ok(())
    }

    /// Attend une commande du lecteur (timeout 5 s par défaut).
    /// Le PN532 strip le CRC-A avant de retourner les données.
    pub fn tg_get_data(&mut self) -> anyhow::Result<heapless::Vec<u8, 32>> {
        self.send_frame(CMD_TG_GET_DATA, &[])?;
        self.read_ack()?;
        let resp = self.read_response_target(CMD_TG_GET_DATA, 500)?;
        if resp.first().copied().unwrap_or(1) != 0x00 {
            return Err(anyhow::anyhow!(
                "TgGetData: status {:02X}",
                resp.first().copied().unwrap_or(0xFF)
            ));
        }
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        for &b in resp.iter().skip(1) {
            data.push(b).ok();
        }
        Ok(data)
    }

    /// Envoie une réponse au lecteur. Le PN532 append le CRC-A automatiquement.
    pub fn tg_set_data(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.send_frame(CMD_TG_SET_DATA, data)?;
        self.read_ack()?;
        let resp = self.read_response(CMD_TG_SET_DATA)?;
        if resp.first().copied().unwrap_or(1) != 0x00 {
            return Err(anyhow::anyhow!("TgSetData: erreur"));
        }
        Ok(())
    }

    /// Variante de read_response avec timeout étendu (N × 10ms).
    fn read_response_target(
        &mut self,
        cmd: u8,
        max_tries: u32,
    ) -> anyhow::Result<heapless::Vec<u8, 32>> {
        self.wait_ready(max_tries)?;
        let mut buf = [0u8; 32];
        self.i2c
            .read(PN532_ADDR, &mut buf, BLOCK)
            .map_err(|e| anyhow::anyhow!("PN532 read: {:?}", e))?;
        if buf[6] != TFI_C2H {
            return Err(anyhow::anyhow!("TFI inattendu: {:#02x}", buf[6]));
        }
        if buf[7] != cmd.wrapping_add(1) {
            return Err(anyhow::anyhow!("CMD inattendue: {:#02x}", buf[7]));
        }
        let len = buf[4] as usize;
        let end = (8 + len.saturating_sub(2)).min(32);
        let mut result: heapless::Vec<u8, 32> = heapless::Vec::new();
        for i in 8..end {
            result.push(buf[i]).ok();
        }
        Ok(result)
    }

    /// Émule un badge MIFARE Classic depuis un dump. Crypto1 géré côté ESP32
    /// (le PN532 relaie les octets bruts) : AUTH (NT aléatoire, vérifie AR, envoie
    /// AT), READ (bloc chiffré), autres commandes → NACK chiffré + reset session.
    pub fn emulate_mifare<F: FnMut(&str)>(
        &mut self,
        dump: &MifareDump,
        keys: &[attacks::SectorKey],
        mut status: F,
    ) -> EmulResult {
        use axolotl_core::crypto1::Crypto1;

        // UID depuis bloc 0
        let b0 = dump.blocks[0];
        let uid4 = [b0[0], b0[1], b0[2], b0[3]];
        let uid32 = u32::from_be_bytes(uid4);
        let (sak, atqa) = match dump.card_type {
            ClassicType::Classic4K => (0x18u8, [0x02u8, 0x00u8]),
            ClassicType::Mini => (0x09u8, [0x04u8, 0x00u8]),
            _ => (0x08u8, [0x04u8, 0x00u8]),
        };

        // Pas de lecteur dans la fenêtre d'attente → Timeout propre ("pas de
        // lecteur") plutôt qu'une erreur "PN532 timeout" qui n'aide pas l'user.
        status("Approche lecteur...");
        if self.tg_init_as_target(&uid4, sak, atqa).is_err() {
            return EmulResult::Timeout;
        }
        status("Lecteur detecte");

        let mut crypto: Option<(Crypto1, u32)> = None; // (state, auth_sector)

        loop {
            let frame = match self.tg_get_data() {
                Ok(f) => f,
                Err(_) => return EmulResult::Timeout,
            };

            if frame.is_empty() {
                continue;
            }

            // Décrypter si une session Crypto1 est active
            let cmd_byte = if let Some((ref mut s, _)) = crypto {
                frame[0] ^ s.keystream_byte()
            } else {
                frame[0]
            };

            match cmd_byte {
                // ── Authentification ───────────────────────────────────────
                0x60 | 0x61 => {
                    let key_ab: u8 = if cmd_byte == 0x60 { 0 } else { 1 };
                    // Pour nested auth, le bloc est chiffré — on le déchiffre avant de reset.
                    // (Pour le premier auth, crypto=None donc raw_block est en clair.)
                    let raw_block = frame.get(1).copied().unwrap_or(0);
                    let block = if let Some((ref mut s, _)) = crypto.as_mut() {
                        raw_block ^ s.keystream_byte()
                    } else {
                        raw_block
                    };
                    crypto = None; // reset après décryptage du numéro de bloc
                                   // Numéro de secteur depuis le numéro de bloc
                    let sector = block_to_sector(dump.card_type, block);

                    // Cherche la clé pour ce secteur
                    let key = keys
                        .iter()
                        .find(|k| k.sector == sector && k.key_ab == key_ab)
                        .map(|k| k.key)
                        .or_else(|| {
                            let t = dump.card_type.sector_trailer(sector)? as usize;
                            let slice = if key_ab == 0 {
                                &dump.blocks[t][0..6]
                            } else {
                                &dump.blocks[t][10..16]
                            };
                            slice.try_into().ok()
                        });

                    let key = match key {
                        Some(k) => k,
                        None => {
                            let _ = self.tg_set_data(&[0x05]); // NACK
                            status("Auth: cle manquante");
                            continue;
                        }
                    };

                    // NT aléatoire via timer µs (pas besoin de vraie RNG, juste unique)
                    let nt32 =
                        unsafe { esp_idf_svc::sys::esp_timer_get_time() } as u32 ^ 0xA5F0_1234;
                    let nt_bytes = nt32.to_be_bytes();

                    if self.tg_set_data(&nt_bytes).is_err() {
                        return EmulResult::Error("envoi NT".into());
                    }

                    // Reçoit {NR_enc, AR_enc} (8 bytes)
                    let nr_ar = match self.tg_get_data() {
                        Ok(d) => d,
                        Err(_) => return EmulResult::Timeout,
                    };
                    if nr_ar.len() < 8 {
                        let _ = self.tg_set_data(&[0x05]);
                        continue;
                    }

                    let key64 =
                        u64::from_be_bytes([0, 0, key[0], key[1], key[2], key[3], key[4], key[5]]);
                    let mut s = Crypto1::init_auth(key64, uid32, nt32);

                    let ks1 = s.keystream_word();
                    let nr_enc = u32::from_be_bytes([nr_ar[0], nr_ar[1], nr_ar[2], nr_ar[3]]);
                    let nr = nr_enc ^ ks1;
                    s.word_in(nr, false); // avance l'état avec NR réel

                    let ks2 = s.keystream_word();
                    let ar_enc = u32::from_be_bytes([nr_ar[4], nr_ar[5], nr_ar[6], nr_ar[7]]);
                    let ar_plain = ar_enc ^ ks2;

                    // AR attendu = ROL(NT, 1)
                    if ar_plain != nt32.rotate_left(1) {
                        let _ = self.tg_set_data(&[0x05]);
                        status("Auth: AR incorrect");
                        continue;
                    }

                    // AT = ROL(NT, 2), chiffré avec ks3
                    let ks3 = s.keystream_word();
                    let at_enc = (nt32.rotate_left(2) ^ ks3).to_be_bytes();
                    if self.tg_set_data(&at_enc).is_err() {
                        return EmulResult::Error("envoi AT".into());
                    }

                    crypto = Some((s, sector as u32));
                    let msg = format!("Auth OK S{}", sector);
                    status(&msg);
                }

                // ── Lecture ────────────────────────────────────────────────
                MIFARE_READ => {
                    let (s, _sec) = match crypto.as_mut() {
                        Some(c) => c,
                        None => {
                            let _ = self.tg_set_data(&[0x05]);
                            continue;
                        }
                    };
                    // Décrypter le numéro de bloc (déjà décrypté via cmd_byte ci-dessus)
                    let block = frame.get(1).copied().unwrap_or(0) ^ s.keystream_byte();
                    let block_usize = block as usize;

                    let block_data = if block_usize < dump.blocks.len() {
                        dump.blocks[block_usize]
                    } else {
                        [0u8; 16]
                    };

                    // Chiffrer les 16 bytes de réponse avec le keystream courant
                    let mut enc = [0u8; 16];
                    for (i, b) in block_data.iter().enumerate() {
                        enc[i] = b ^ s.keystream_byte();
                    }
                    if self.tg_set_data(&enc).is_err() {
                        return EmulResult::Error("envoi READ".into());
                    }
                }

                // ── Écriture (ignorée — badge en lecture seule) ────────────
                MIFARE_WRITE => {
                    if let Some((ref mut s, _)) = crypto {
                        // ACK (chiffré) puis ignorer les 16 bytes data
                        let ack = 0x0Au8 ^ s.keystream_byte();
                        let _ = self.tg_set_data(&[ack]);
                    }
                }

                // ── Déconnexion / commande inconnue ────────────────────────
                _ => {
                    crypto = None;
                    // Tentative de ré-init cible pour le prochain passage
                    if self.tg_init_as_target(&uid4, sak, atqa).is_err() {
                        return EmulResult::Done;
                    }
                    status("Pret — attente lecteur");
                }
            }
        }
    }
}

/// Convertit un numéro de bloc en numéro de secteur selon le type de carte.
fn block_to_sector(card_type: ClassicType, block: u8) -> u8 {
    match card_type {
        ClassicType::Classic4K if block >= 128 => 32 + (block - 128) / 16,
        _ => block / 4,
    }
}

/// Log un dump MIFARE Classic ligne par ligne.
/// Logique de présentation, gardée côté firmware (la struct est dans core).
pub fn print_dump_log(dump: &MifareDump) {
    let total = dump.total_blocks();
    log::info!(
        "=== MIFARE Dump : {}/{} blocs lisibles ===",
        dump.readable_count(),
        total
    );
    // On ne logue QUE les blocs lisibles : sur une carte protégée, lister 64
    // lignes « non lisible » noyait l'info utile. Les numéros illisibles sont
    // résumés en une seule ligne ; le dump complet reste écrit dans le .txt.
    let mut unreadable = String::new();
    for block in 0..total {
        if dump.readable[block] {
            let d = &dump.blocks[block];
            log::info!(
                "Bloc {:03}: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} \
                 {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                block,
                d[0],
                d[1],
                d[2],
                d[3],
                d[4],
                d[5],
                d[6],
                d[7],
                d[8],
                d[9],
                d[10],
                d[11],
                d[12],
                d[13],
                d[14],
                d[15]
            );
        } else {
            if !unreadable.is_empty() {
                unreadable.push(' ');
            }
            unreadable.push_str(&format!("{:03}", block));
        }
    }
    if !unreadable.is_empty() {
        log::info!(
            "Blocs non lisibles ({}) : {}",
            total - dump.readable_count(),
            unreadable
        );
    }
}
