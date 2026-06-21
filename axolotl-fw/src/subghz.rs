//! Sub-GHz CC1101 driver + fonctions Sub-GHz 433/868/315 MHz
//!
//! Câblage : CS=GPIO7, SCK=12, MOSI=11, MISO=13, GDO0=NC, GDO2=NC.
//! SPI2 partagé avec display (MODE_3) et SD (MODE_0). CC1101 = MODE_0, 5MHz.
//!
//! Limitation GDO0=NC : TX/RX en mode paquet FIFO uniquement.
//! Scan RSSI OK. Princeton TX OK (bits encodés dans FIFO). Capture = polling RSSI.

use esp_idf_hal::{
    delay::FreeRtos,
    gpio::AnyOutputPin,
    spi::{config::{Config, MODE_0}, SpiDeviceDriver, SpiDriver},
    units::FromValueType,
};

// ── Constantes registres CC1101 ───────────────────────────────────────────────
const IOCFG0: u8    = 0x02;
const FIFOTHR: u8   = 0x03;
const SYNC1: u8     = 0x04;
const SYNC0: u8     = 0x05;
const PKTLEN: u8    = 0x06;
const PKTCTRL0: u8  = 0x08;
const FSCTRL1: u8   = 0x0B;
const FREQ2: u8     = 0x0D;
const FREQ1: u8     = 0x0E;
const FREQ0: u8     = 0x0F;
const MDMCFG4: u8   = 0x10;
const MDMCFG3: u8   = 0x11;
const MDMCFG2: u8   = 0x12;
const MDMCFG1: u8   = 0x13;
const MDMCFG0: u8   = 0x14;
const DEVIATN: u8   = 0x15;
const MCSM1: u8     = 0x17;
const MCSM0: u8     = 0x18;
const FOCCFG: u8    = 0x19;
const AGCCTRL2: u8  = 0x1B;
const AGCCTRL1: u8  = 0x1C;
const AGCCTRL0: u8  = 0x1D;
const FREND1: u8    = 0x21;
const FREND0: u8    = 0x22;
const FSCAL3: u8    = 0x23;
const FSCAL2: u8    = 0x24;
const FSCAL1: u8    = 0x25;
const FSCAL0: u8    = 0x26;
const PA_TABLE0: u8 = 0x3E;

// Status registers (nécessitent burst+read)
const RSSI_REG: u8  = 0x34;
const MARCSTATE: u8 = 0x35;
const TXBYTES: u8   = 0x3A;
const PARTNUM: u8   = 0x30;
const VERSION: u8   = 0x31;

// FIFO addresse (burst write/read)
const TXFIFO_BURST: u8 = 0x7F; // 0x3F | BURST(0x40)

// Bits SPI
const READ: u8  = 0x80;
const BURST: u8 = 0x40;

// Command strobes
const SRES: u8  = 0x30;
const SRX: u8   = 0x34;
const STX: u8   = 0x35;
const SIDLE: u8 = 0x36;
const SFRX: u8  = 0x3A;
const SFTX: u8  = 0x3B;

// ── Bandes fréquence ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Band {
    Mhz315,
    Mhz433,
    Mhz868,
    Mhz915,
}

impl Band {
    /// Retourne (FREQ2, FREQ1, FREQ0) pour cette bande.
    pub fn freq_regs(self) -> (u8, u8, u8) {
        let khz: u32 = match self {
            Band::Mhz315 => 315_000,
            Band::Mhz433 => 433_920,
            Band::Mhz868 => 868_350,
            Band::Mhz915 => 915_000,
        };
        let freq = (khz as u64 * 1_000 * 65_536 / 26_000_000) as u32;
        ((freq >> 16) as u8, (freq >> 8) as u8, freq as u8)
    }

    pub fn freq_khz(self) -> u32 {
        match self {
            Band::Mhz315 => 315_000,
            Band::Mhz433 => 433_920,
            Band::Mhz868 => 868_350,
            Band::Mhz915 => 915_000,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Band::Mhz315 => "315 MHz",
            Band::Mhz433 => "433 MHz",
            Band::Mhz868 => "868 MHz",
            Band::Mhz915 => "915 MHz",
        }
    }
}

pub const BANDS: &[Band] = &[Band::Mhz433, Band::Mhz315, Band::Mhz868, Band::Mhz915];

// ── Driver ───────────────────────────────────────────────────────────────────

pub struct Cc1101<'d> {
    spi: SpiDeviceDriver<'d, &'d SpiDriver<'d>>,
    pub band: Band,
}

impl<'d> Cc1101<'d> {
    pub fn new(driver: &'d SpiDriver<'d>, cs: AnyOutputPin<'d>) -> anyhow::Result<Self> {
        // 1 MHz sur breadboard pour marge maximale (datasheet max = 10 MHz)
        let spi = SpiDeviceDriver::new(
            driver,
            Some(cs),
            &Config::new().baudrate(1_000_000_u32.Hz()).data_mode(MODE_0),
        )?;
        let mut cc = Self { spi, band: Band::Mhz433 };
        // Délai power-on CC1101 (datasheet: >40µs, on prend 50ms pour breadboard)
        FreeRtos::delay_ms(50);
        cc.reset()?;
        cc.configure_ook(Band::Mhz433)?;
        Ok(cc)
    }

    // ── SPI primitives ────────────────────────────────────────────────────

    fn write_reg(&mut self, addr: u8, val: u8) -> anyhow::Result<()> {
        let buf = [addr & 0x3F, val]; // bit7=0 (write), bit6=0 (single)
        self.spi.write(&buf).map_err(|e| anyhow::anyhow!("cc1101 write: {:?}", e))
    }

    fn read_reg(&mut self, addr: u8) -> anyhow::Result<u8> {
        let tx = [addr | READ, 0x00];
        let mut rx = [0u8; 2];
        self.spi.transfer(&mut rx, &tx).map_err(|e| anyhow::anyhow!("cc1101 read: {:?}", e))?;
        Ok(rx[1])
    }

    fn read_status_reg(&mut self, addr: u8) -> anyhow::Result<u8> {
        // Status registers : bit7=1 (read), bit6=1 (burst)
        let tx = [addr | READ | BURST, 0x00];
        let mut rx = [0u8; 2];
        self.spi.transfer(&mut rx, &tx).map_err(|e| anyhow::anyhow!("cc1101 status: {:?}", e))?;
        Ok(rx[1])
    }

    fn strobe(&mut self, cmd: u8) -> anyhow::Result<u8> {
        let tx = [cmd, 0x00];
        let mut rx = [0u8; 2];
        self.spi.transfer(&mut rx, &tx).map_err(|e| anyhow::anyhow!("cc1101 strobe: {:?}", e))?;
        Ok(rx[0])
    }

    fn burst_write(&mut self, addr_byte: u8, data: &[u8]) -> anyhow::Result<()> {
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(addr_byte);
        buf.extend_from_slice(data);
        self.spi.write(&buf).map_err(|e| anyhow::anyhow!("cc1101 burst_write: {:?}", e))
    }

    fn burst_read(&mut self, addr_byte: u8, out: &mut [u8]) -> anyhow::Result<()> {
        let tx_len = 1 + out.len();
        let tx: Vec<u8> = std::iter::once(addr_byte).chain(std::iter::repeat(0x00).take(out.len())).collect();
        let mut rx = vec![0u8; tx_len];
        self.spi.transfer(&mut rx, &tx).map_err(|e| anyhow::anyhow!("cc1101 burst_read: {:?}", e))?;
        out.copy_from_slice(&rx[1..]);
        Ok(())
    }

    // ── Init ──────────────────────────────────────────────────────────────

    fn reset(&mut self) -> anyhow::Result<()> {
        // Séquence CC1101 datasheet §10.1 : SNOP pour flush le bus SPI
        // puis SRES. Certains clones requièrent plusieurs tentatives.
        let _ = self.strobe(0x3D); // SNOP — dummy transaction
        FreeRtos::delay_ms(5);
        self.strobe(SRES)?;
        FreeRtos::delay_ms(20);
        let _ = self.strobe(0x3D); // SNOP de vérification
        FreeRtos::delay_ms(5);
        Ok(())
    }

    pub fn check_present(&mut self) -> bool {
        let pn  = self.read_status_reg(PARTNUM).unwrap_or(0xFF);
        let ver = self.read_status_reg(VERSION).unwrap_or(0xFF);
        // Lire aussi IOCFG0 (registre config, doit valoir 0x2E après configure_ook)
        let io0 = self.read_reg(IOCFG0).unwrap_or(0xFF);
        log::info!("CC1101 PARTNUM={:#02x} VERSION={:#02x} IOCFG0={:#02x}", pn, ver, io0);
        // CC1101 officiel : PARTNUM=0x00, VERSION=0x04 ou 0x14
        // Certains clones : VERSION=0x00 ou 0x06 — on accepte si PARTNUM=0x00
        pn == 0x00
    }

    /// Configure en mode OOK/ASK — base pour Princeton et raw 433/868/315 MHz.
    pub fn configure_ook(&mut self, band: Band) -> anyhow::Result<()> {
        self.strobe(SIDLE)?;
        FreeRtos::delay_ms(5);

        let (f2, f1, f0) = band.freq_regs();
        self.write_reg(FREQ2, f2)?;
        self.write_reg(FREQ1, f1)?;
        self.write_reg(FREQ0, f0)?;

        self.write_reg(IOCFG0, 0x2E)?;    // GDO0 = HiZ (NC)
        self.write_reg(FIFOTHR, 0x47)?;
        self.write_reg(PKTCTRL0, 0x02)?;   // infinite packet length, no CRC, no whitening
        self.write_reg(PKTLEN, 0xFF)?;
        self.write_reg(SYNC1, 0x00)?;
        self.write_reg(SYNC0, 0x00)?;

        // ASK/OOK, no sync word detection
        self.write_reg(MDMCFG4, 0xC7)?;
        self.write_reg(MDMCFG3, 0x83)?;   // ~1200 bps (ajusté dans send_princeton)
        self.write_reg(MDMCFG2, 0x30)?;   // OOK, no preamble, no sync
        self.write_reg(MDMCFG1, 0x22)?;
        self.write_reg(MDMCFG0, 0xF8)?;

        self.write_reg(DEVIATN, 0x15)?;
        self.write_reg(MCSM1, 0x30)?;     // idle after RX/TX
        self.write_reg(MCSM0, 0x18)?;
        self.write_reg(FOCCFG, 0x1D)?;
        self.write_reg(FSCTRL1, 0x06)?;

        self.write_reg(AGCCTRL2, 0x03)?;
        self.write_reg(AGCCTRL1, 0x00)?;
        self.write_reg(AGCCTRL0, 0x91)?;

        self.write_reg(FREND1, 0x56)?;
        self.write_reg(FREND0, 0x11)?;    // PA power index 1

        self.write_reg(FSCAL3, 0xE9)?;
        self.write_reg(FSCAL2, 0x2A)?;
        self.write_reg(FSCAL1, 0x00)?;
        self.write_reg(FSCAL0, 0x1F)?;

        // PA_TABLE : +12dBm à 433MHz (0xC3), ou ajuster selon bande
        let pa_val: u8 = match band {
            Band::Mhz433 => 0xC3,
            Band::Mhz315 => 0xC0,
            Band::Mhz868 => 0xC3,
            Band::Mhz915 => 0xC3,
        };
        self.write_reg(PA_TABLE0, pa_val)?;

        self.band = band;
        log::info!("CC1101 OOK configure {} (FREQ={:02X}{:02X}{:02X})", band.name(), f2, f1, f0);
        Ok(())
    }

    pub fn set_band(&mut self, band: Band) -> anyhow::Result<()> {
        self.configure_ook(band)
    }

    // ── RSSI ──────────────────────────────────────────────────────────────

    /// RSSI instantané en dBm (CC1101: raw/2 - 74).
    pub fn rssi_dbm(&mut self) -> anyhow::Result<i16> {
        let raw = self.read_status_reg(RSSI_REG)? as i16;
        Ok(if raw >= 128 { (raw - 256) / 2 - 74 } else { raw / 2 - 74 })
    }

    /// Scan RSSI ±1 MHz autour de la fréquence courante, pas 100 kHz.
    /// Retourne Vec<(offset_khz, rssi_dbm)> — offset relatif à la fréquence centrale.
    pub fn scan_rssi(&mut self, steps: u32, step_khz: u32) -> anyhow::Result<Vec<(i32, i16)>> {
        let half = (steps as i32) / 2;
        let base = self.band.freq_khz();
        let mut results = Vec::new();

        for i in -half..=half {
            let f = (base as i32 + i * step_khz as i32).max(300_000) as u32;
            let freq_val = (f as u64 * 1_000 * 65_536 / 26_000_000) as u32;
            self.strobe(SIDLE)?;
            self.write_reg(FREQ2, (freq_val >> 16) as u8)?;
            self.write_reg(FREQ1, (freq_val >> 8) as u8)?;
            self.write_reg(FREQ0, freq_val as u8)?;
            self.strobe(SRX)?;
            FreeRtos::delay_ms(8);
            let dbm = self.rssi_dbm()?;
            results.push((i * step_khz as i32, dbm));
        }
        // Restaure
        let (f2, f1, f0) = self.band.freq_regs();
        self.strobe(SIDLE)?;
        self.write_reg(FREQ2, f2)?;
        self.write_reg(FREQ1, f1)?;
        self.write_reg(FREQ0, f0)?;
        Ok(results)
    }

    // ── TX Princeton OOK ─────────────────────────────────────────────────

    /// Envoie un payload Princeton OOK.
    /// `bits` : slice de u8 (0 ou 1), `te_us` : durée base en µs (typiquement 300-500).
    /// Le CC1101 est configuré à data rate = 1/te_us bps.
    /// Chaque bit Princeton est encodé en 4 bits CC1101 :
    ///   '1' → 0b1110 (3×TE haut + 1×TE bas)
    ///   '0' → 0b1000 (1×TE haut + 3×TE bas)
    /// `repeat` : nombre de répétitions (typique = 5–10 pour garage).
    pub fn send_princeton(&mut self, bits: &[u8], te_us: u32, repeat: u8) -> anyhow::Result<()> {
        let dr_bps = 1_000_000u32.saturating_div(te_us.max(50));
        let (m4, m3) = bps_to_mdmcfg(dr_bps);

        self.strobe(SIDLE)?;
        self.write_reg(MDMCFG4, m4)?;
        self.write_reg(MDMCFG3, m3)?;
        self.strobe(SFTX)?;

        // Encode bits Princeton → bytes OOK
        let mut payload: Vec<u8> = Vec::new();
        // Garde initial (RF off)
        for _ in 0..4 { payload.push(0x00); }
        for &bit in bits {
            // On groupe 2 bits Princeton par byte (4 bits chacun = 8 bits)
            let nibble: u8 = if bit != 0 { 0xE } else { 0x8 }; // 1110 ou 1000
            // On paque deux nibbles par byte, mais on simplifie avec 1 byte = 1 bit Princeton
            // (les 4 bits haut du byte = OOK pattern, 4 bits bas = début du prochain)
            payload.push((nibble << 4) | 0x00);
        }
        // Sync (31×TE bas) : ~8 bytes de 0x00
        for _ in 0..8 { payload.push(0x00); }

        for _ in 0..repeat {
            self.strobe(SFTX)?;
            // Envoyer en chunks de 60 bytes
            let mut pos = 0usize;
            let mut tx_started = false;
            while pos < payload.len() {
                let end = (pos + 60).min(payload.len());
                self.burst_write(TXFIFO_BURST, &payload[pos..end])?;
                if !tx_started {
                    self.strobe(STX)?;
                    tx_started = true;
                }
                pos = end;
                // Attendre que le FIFO ait de la place
                for _ in 0..200u32 {
                    let nb = self.read_status_reg(TXBYTES)? & 0x7F;
                    if nb < 32 { break; }
                    FreeRtos::delay_ms(1);
                }
            }
            // Attendre fin TX
            for _ in 0..500u32 {
                let state = self.read_status_reg(MARCSTATE)? & 0x1F;
                if state == 0x01 || state == 0x16 { break; } // IDLE ou TXFIFO_UNDERFLOW
                FreeRtos::delay_ms(2);
            }
        }

        self.strobe(SIDLE)?;
        self.strobe(SFTX)?;
        log::info!("CC1101 Princeton : {} bits × {} @ {}µs TE", bits.len(), repeat, te_us);
        Ok(())
    }

    // ── Capture RSSI (GDO0=NC, polling) ─────────────────────────────────

    /// Surveille le RSSI pendant `timeout_ms` ms et détecte les pics.
    /// Retourne le RSSI max observé et la durée d'activité en ms.
    pub fn monitor_rssi(&mut self, timeout_ms: u32, threshold_dbm: i16) -> anyhow::Result<RssiCapture> {
        self.strobe(SIDLE)?;
        self.strobe(SFRX)?;
        self.strobe(SRX)?;
        FreeRtos::delay_ms(5);

        let start = unsafe { esp_idf_svc::sys::esp_timer_get_time() };
        let deadline = start + timeout_ms as i64 * 1_000;
        let mut max_dbm: i16 = -120;
        let mut active_ms: u32 = 0;
        let mut peak_count: u32 = 0;

        while unsafe { esp_idf_svc::sys::esp_timer_get_time() } < deadline {
            let dbm = self.rssi_dbm()?;
            if dbm > max_dbm { max_dbm = dbm; }
            if dbm > threshold_dbm {
                active_ms += 2;
                peak_count += 1;
            }
            FreeRtos::delay_ms(2);
        }

        self.strobe(SIDLE)?;
        Ok(RssiCapture { max_dbm, active_ms, peak_count })
    }

    /// Capture brute de pulses via polling RSSI (approximatif — GDO0=NC).
    /// Retourne Vec de durées en µs avec polarité (0=bas/1=haut).
    pub fn capture_pulses(&mut self, timeout_ms: u32, threshold_dbm: i16) -> anyhow::Result<Vec<Pulse>> {
        self.strobe(SIDLE)?;
        self.strobe(SFRX)?;
        self.strobe(SRX)?;
        FreeRtos::delay_ms(5);

        let start_us = unsafe { esp_idf_svc::sys::esp_timer_get_time() };
        let deadline_us = start_us + timeout_ms as i64 * 1_000;
        let mut pulses: Vec<Pulse> = Vec::new();
        let mut last_level: u8 = 0;
        let mut last_us = start_us;

        while unsafe { esp_idf_svc::sys::esp_timer_get_time() } < deadline_us && pulses.len() < 512 {
            let dbm = self.rssi_dbm()?;
            let level: u8 = if dbm > threshold_dbm { 1 } else { 0 };
            if level != last_level {
                let now = unsafe { esp_idf_svc::sys::esp_timer_get_time() };
                let dur = (now - last_us).max(1) as u32;
                pulses.push(Pulse { dur_us: dur, level: last_level });
                last_us = now;
                last_level = level;
            }
            FreeRtos::delay_ms(2);
        }
        self.strobe(SIDLE)?;
        log::info!("CC1101 capture : {} pulses", pulses.len());
        Ok(pulses)
    }

    /// Rejoue une séquence de pulses capturée via FIFO OOK.
    /// Approximatif : level=1 → 0xFF bytes, level=0 → 0x00 bytes.
    pub fn replay_pulses(&mut self, pulses: &[Pulse], te_us: u32) -> anyhow::Result<()> {
        if pulses.is_empty() { return Ok(()); }
        // Data rate = 1_000_000 / te_us
        let dr_bps = 1_000_000u32.saturating_div(te_us.max(50));
        let (m4, m3) = bps_to_mdmcfg(dr_bps);

        self.strobe(SIDLE)?;
        self.write_reg(MDMCFG4, m4)?;
        self.write_reg(MDMCFG3, m3)?;
        self.strobe(SFTX)?;

        // Encode pulses en bytes OOK : chaque byte ~ 1 TE
        let mut payload: Vec<u8> = Vec::new();
        for p in pulses {
            let n_bits = (p.dur_us / te_us.max(50)).max(1).min(64) as usize;
            let fill = if p.level == 1 { 0xFFu8 } else { 0x00u8 };
            for _ in 0..n_bits { payload.push(fill); }
        }

        let mut pos = 0usize;
        let mut tx_started = false;
        while pos < payload.len() {
            let end = (pos + 60).min(payload.len());
            self.burst_write(TXFIFO_BURST, &payload[pos..end])?;
            if !tx_started {
                self.strobe(STX)?;
                tx_started = true;
            }
            pos = end;
            for _ in 0..200u32 {
                if self.read_status_reg(TXBYTES)? & 0x7F < 32 { break; }
                FreeRtos::delay_ms(1);
            }
        }
        for _ in 0..500u32 {
            let s = self.read_status_reg(MARCSTATE)? & 0x1F;
            if s == 0x01 || s == 0x16 { break; }
            FreeRtos::delay_ms(2);
        }
        self.strobe(SIDLE)?;
        self.strobe(SFTX)?;
        Ok(())
    }
}

// ── Types de retour ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct RssiCapture {
    pub max_dbm: i16,
    pub active_ms: u32,
    pub peak_count: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Pulse {
    pub dur_us: u32,
    pub level: u8,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convertit un data rate bps en (MDMCFG4, MDMCFG3) pour CC1101 (Xosc=26MHz).
fn bps_to_mdmcfg(bps: u32) -> (u8, u8) {
    // Valeurs empiriques calibrées pour les data rates courants
    match bps {
        0..=800     => (0xF5, 0x83), // 600 bps
        801..=1500  => (0xF5, 0x83), // 1.2 kbps
        1501..=3000 => (0xF6, 0x83), // 2.4 kbps
        3001..=6000 => (0xC7, 0x43), // 4.8 kbps
        6001..=15000 => (0xC8, 0x93),// 9.6 kbps
        _            => (0xCA, 0x83),// 38.4 kbps
    }
}
