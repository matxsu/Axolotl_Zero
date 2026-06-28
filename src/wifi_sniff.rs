use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::*;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::Text,
};
use ::log::info;

const BOX_SSID: &str = "Livebox-58B8";
const CANAL_DEFAUT: u8 = 6;

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

    // DIAG : logge tout 88 8E avec les octets suivants (sans filtre strict).
    let mut i = 0usize;
    while i + 8 < len {
        if *payload.add(i) == 0x88 && *payload.add(i + 1) == 0x8E {
            info!("HIT off={} : {:02X} {:02X} {:02X} {:02X}",
                i, *payload.add(i + 2), *payload.add(i + 3),
                *payload.add(i + 4), *payload.add(i + 5));
        }
        if *payload.add(i) == 0x88
            && *payload.add(i + 1) == 0x8E
            && (*payload.add(i + 2) == 0x01 || *payload.add(i + 2) == 0x02)
            && *payload.add(i + 3) == 0x03
        {
            N_EAPOL.fetch_add(1, Ordering::Relaxed);
            // ethertype a i,i+1 ; eapol a i+2 ; Key Information a i+7.
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
            let mut s = String::with_capacity(len * 2);
            for k in 0..len {
                s.push_str(&format!("{:02X}", *payload.add(k)));
            }
            info!("PCAP:{}", s);
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
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(title, Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(l1, Point::new(8, 60), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(l2, Point::new(8, 80), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

pub fn run<D>(
    modem: Modem,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    display: &mut D,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    info!("=== Sniffer 802.11 / capture handshake ===");

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;

    banner(display, "Capture handshake", "Recherche de la box", BOX_SSID)?;
    let mut reseaux = wifi.scan()?;
    let mut essais = 0;
    while essais < 8 && !reseaux.iter().any(|ap| ap.ssid.as_str() == BOX_SSID) {
        FreeRtos::delay_ms(400);
        reseaux = wifi.scan()?;
        essais += 1;
    }
    let mut canal = CANAL_DEFAUT;
    let mut trouve = false;
    for ap in reseaux.iter() {
        info!("scan: {} canal {}", ap.ssid.as_str(), ap.channel);
        if ap.ssid.as_str() == BOX_SSID {
            canal = ap.channel;
            trouve = true;
        }
    }
    if trouve {
        let l1 = format!("Box '{}' trouvee", BOX_SSID);
        let l2 = format!("Canal : {}", canal);
        banner(display, "Capture handshake", &l1, &l2)?;
    } else {
        let l2 = format!("Canal defaut : {}", canal);
        banner(display, "Capture handshake", "Box non trouvee", &l2)?;
    }
    FreeRtos::delay_ms(3000);

    unsafe {
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(Some(rx_cb));
        esp_wifi_set_channel(canal, wifi_second_chan_t_WIFI_SECOND_CHAN_NONE);
    }
    info!("Promiscuous actif sur le canal {}", canal);

    let style = MonoTextStyle::new(&FONT_6X10, WHITE);
    loop {
        let total = N_TOTAL.load(Ordering::Relaxed);
        let mgmt = N_MGMT.load(Ordering::Relaxed);
        let data = N_DATA.load(Ordering::Relaxed);
        let eapol = N_EAPOL.load(Ordering::Relaxed);
        let seen = MSG_SEEN.load(Ordering::Relaxed);

        display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Rectangle::new(Point::new(0, 0), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
            .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new("Capture handshake", Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
            .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let l1 = format!("Canal     : {}", canal);
        let l2 = format!("Trames    : {}", total);
        let l3 = format!("Management: {}", mgmt);
        let l4 = format!("Data      : {}   EAPOL : {}", data, eapol);
        Text::new(&l1, Point::new(8, 52), style).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new(&l2, Point::new(8, 69), style).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new(&l3, Point::new(8, 86), style).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new(&l4, Point::new(8, 103), style).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

        Text::new("Handshake :", Point::new(8, 130), style)
            .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        for m in 0..4u32 {
            let vu = (seen & (1 << m)) != 0;
            let col = if vu { GREEN } else { GRAY };
            let label = format!("M{}", m + 1);
            Text::new(&label, Point::new(100 + (m as i32) * 32, 130), MonoTextStyle::new(&FONT_6X10, col))
                .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }

        if seen == 0x0F {
            Text::new("HANDSHAKE COMPLET 4/4 !", Point::new(8, 160), MonoTextStyle::new(&FONT_6X10, GREEN))
                .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }

        FreeRtos::delay_ms(300);
    }
}
