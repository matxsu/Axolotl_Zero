//! Sniffer 802.11 en mode promiscuous + détection de handshake WPA (EAPOL).
//! Sauvegarde PCAP sur flash interne (/spiflash) ou SD.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use ::log::info;
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::Text,
};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use esp_idf_svc::hal::modem::WifiModemPeripheral;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::*;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const GREEN: Rgb565 = Rgb565::new(6, 50, 8);

static N_TOTAL: AtomicU32 = AtomicU32::new(0);
static N_MGMT: AtomicU32 = AtomicU32::new(0);
static N_DATA: AtomicU32 = AtomicU32::new(0);
static N_EAPOL: AtomicU32 = AtomicU32::new(0);
static MSG_SEEN: AtomicU32 = AtomicU32::new(0);

static CAPTURED: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
const MAX_CAPTURED: usize = 200;

unsafe extern "C" fn rx_cb(buf: *mut c_void, pkt_type: u32) {
    N_TOTAL.fetch_add(1, Ordering::Relaxed);
    if pkt_type == wifi_promiscuous_pkt_type_t_WIFI_PKT_MGMT {
        N_MGMT.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if pkt_type != wifi_promiscuous_pkt_type_t_WIFI_PKT_DATA || buf.is_null() {
        return;
    }
    N_DATA.fetch_add(1, Ordering::Relaxed);

    let pkt = buf as *const wifi_promiscuous_pkt_t;
    let len = (*pkt).rx_ctrl.sig_len() as usize;
    let payload = (*pkt).payload.as_ptr();

    let mut i = 0usize;
    while i + 8 < len {
        if *payload.add(i) == 0x88
            && *payload.add(i + 1) == 0x8E
            && (*payload.add(i + 2) == 0x01 || *payload.add(i + 2) == 0x02)
            && *payload.add(i + 3) == 0x03
        {
            N_EAPOL.fetch_add(1, Ordering::Relaxed);
            let ki = ((*payload.add(i + 7) as u16) << 8) | (*payload.add(i + 8) as u16);
            let install = ki & 0x0040 != 0;
            let ack = ki & 0x0080 != 0;
            let mic = ki & 0x0100 != 0;
            let secure = ki & 0x0200 != 0;
            let (bit, label) = if ack && !mic {
                (1u32 << 0, 1)
            } else if !ack && mic && !secure {
                (1u32 << 1, 2)
            } else if ack && mic && install && secure {
                (1u32 << 2, 3)
            } else if !ack && mic && secure {
                (1u32 << 3, 4)
            } else {
                (0u32, 0)
            };
            if bit != 0 {
                MSG_SEEN.fetch_or(bit, Ordering::Relaxed);
                info!("EAPOL M{} ki={:04X}", label, ki);
            }
            if let Ok(mut g) = CAPTURED.lock() {
                if g.len() < MAX_CAPTURED {
                    let mut frame = Vec::with_capacity(len);
                    for k in 0..len {
                        frame.push(*payload.add(k));
                    }
                    g.push(frame);
                }
            }
            return;
        }
        i += 1;
    }
}

fn banner<D>(display: &mut D, title: &str, l1: &str, l2: &str) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(crate::anyhow_dbg)?;
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
    Text::new(
        title,
        Point::new(8, 19),
        MonoTextStyle::new(&FONT_6X10, ORANGE),
    )
    .draw(display)
    .map_err(crate::anyhow_dbg)?;
    Text::new(l1, Point::new(8, 60), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
    Text::new(l2, Point::new(8, 80), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
    Ok(())
}

fn storage_root() -> &'static str {
    if std::fs::metadata("/sdcard").is_ok() {
        "/sdcard"
    } else {
        "/spiflash"
    }
}

fn save_handshakes_pcap(ssid: &str) -> anyhow::Result<Option<String>> {
    use std::io::Write;
    let frames = {
        let mut g = CAPTURED
            .lock()
            .map_err(|_| anyhow::anyhow!("CAPTURED lock"))?;
        std::mem::take(&mut *g)
    };
    if frames.is_empty() {
        return Ok(None);
    }

    let root = storage_root();
    let dir = format!("{}/loot/handshakes", root);
    std::fs::create_dir_all(&dir)?;
    let safe: String = ssid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(20)
        .collect();
    let name = if safe.is_empty() {
        "cap".to_string()
    } else {
        safe
    };
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = format!("{}/{}-{}.pcap", dir, name, n);

    let mut f =
        std::fs::File::create(&path).map_err(|e| anyhow::anyhow!("PCAP create {}: {}", path, e))?;
    f.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
    f.write_all(&2u16.to_le_bytes())?;
    f.write_all(&4u16.to_le_bytes())?;
    f.write_all(&0i32.to_le_bytes())?;
    f.write_all(&0u32.to_le_bytes())?;
    f.write_all(&65535u32.to_le_bytes())?;
    f.write_all(&105u32.to_le_bytes())?;
    for (i, fr) in frames.iter().enumerate() {
        f.write_all(&(i as u32).to_le_bytes())?;
        f.write_all(&0u32.to_le_bytes())?;
        f.write_all(&(fr.len() as u32).to_le_bytes())?;
        f.write_all(&(fr.len() as u32).to_le_bytes())?;
        f.write_all(fr)?;
    }
    f.flush()?;
    info!("PCAP: {} ({} trames)", path, frames.len());
    Ok(Some(path))
}

#[allow(clippy::too_many_arguments)]
pub fn run<D>(
    modem: impl WifiModemPeripheral,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    display: &mut D,
    back: &PinDriver<'_, Input>,
    target_ssid: &str,
    channel: u8,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    info!("Sniff WPA: {} ch {}", target_ssid, channel);
    for c in [&N_TOTAL, &N_MGMT, &N_DATA, &N_EAPOL, &MSG_SEEN] {
        c.store(0, Ordering::Relaxed);
    }
    if let Ok(mut g) = CAPTURED.lock() {
        g.clear();
    }

    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;

    banner(
        display,
        "Capture handshake",
        &format!("Cible: {:.18}", target_ssid),
        &format!("Canal: {}", channel),
    )?;
    FreeRtos::delay_ms(1500);

    unsafe {
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(Some(rx_cb));
        esp_wifi_set_channel(channel, wifi_second_chan_t_WIFI_SECOND_CHAN_NONE);
    }

    let style = MonoTextStyle::new(&FONT_6X10, WHITE);
    let saved = false;
    loop {
        if back.is_low() {
            unsafe {
                esp_wifi_set_promiscuous_rx_cb(None);
                esp_wifi_set_promiscuous(false);
            }
            if !saved {
                match save_handshakes_pcap(target_ssid) {
                    Ok(Some(path)) => {
                        banner(display, "Capture handshake", "PCAP sauvé:", &path)?;
                        FreeRtos::delay_ms(3000);
                    }
                    Ok(None) => info!("Aucun EAPOL"),
                    Err(e) => ::log::warn!("PCAP KO: {:?}", e),
                }
            }
            return Ok(());
        }
        let total = N_TOTAL.load(Ordering::Relaxed);
        let data = N_DATA.load(Ordering::Relaxed);
        let eapol = N_EAPOL.load(Ordering::Relaxed);
        let seen = MSG_SEEN.load(Ordering::Relaxed);

        display.clear(BG).map_err(crate::anyhow_dbg)?;
        Rectangle::new(Point::new(0, 0), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        Text::new(
            "Capture handshake",
            Point::new(8, 19),
            MonoTextStyle::new(&FONT_6X10, ORANGE),
        )
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
        Text::new(
            &format!("Canal:{} Trames:{}", channel, total),
            Point::new(8, 52),
            style,
        )
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
        Text::new(
            &format!("Data:{} EAPOL:{}", data, eapol),
            Point::new(8, 69),
            style,
        )
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
        Text::new("Handshake:", Point::new(8, 100), style)
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        for m in 0..4u32 {
            let vu = (seen & (1 << m)) != 0;
            Text::new(
                &format!("M{}", m + 1),
                Point::new(100 + (m as i32) * 32, 100),
                MonoTextStyle::new(&FONT_6X10, if vu { GREEN } else { GRAY }),
            )
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        }
        if seen == 0x0F {
            Text::new(
                "HANDSHAKE 4/4!",
                Point::new(8, 130),
                MonoTextStyle::new(&FONT_6X10, GREEN),
            )
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        }
        FreeRtos::delay_ms(300);
    }
}
