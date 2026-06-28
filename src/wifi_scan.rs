use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi, AuthMethod};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::Text,
};
use log::info;

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const GREEN: Rgb565 = Rgb565::new(6, 50, 8);
const RED: Rgb565 = Rgb565::new(28, 8, 6);
const DIM: Rgb565 = Rgb565::new(16, 34, 20);

fn auth_court(a: Option<AuthMethod>) -> &'static str {
    match a {
        None => "OPN",
        Some(AuthMethod::None) => "OPN",
        Some(AuthMethod::WEP) => "WEP",
        Some(AuthMethod::WPA) => "WPA",
        Some(AuthMethod::WPA2Personal) => "WPA2",
        Some(AuthMethod::WPAWPA2Personal) => "WPA2",
        Some(AuthMethod::WPA2Enterprise) => "WPA2E",
        Some(AuthMethod::WPA3Personal) => "WPA3",
        Some(AuthMethod::WPA2WPA3Personal) => "WPA3",
        _ => "?",
    }
}

fn barres(rssi: i8) -> u8 {
    if rssi >= -50 { 4 }
    else if rssi >= -60 { 3 }
    else if rssi >= -70 { 2 }
    else { 1 }
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
    info!("=== Demarrage du scanner WiFi ===");
    banner(display, "Scan en cours...")?;
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;
    info!("WiFi demarre en mode station");

    loop {
        info!("--- Nouveau scan ---");
        let reseaux = wifi.scan()?;
        info!("{} reseaux trouves", reseaux.len());

        display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Rectangle::new(Point::new(0, 0), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
            .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new("Scan WiFi", Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
            .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        let total = format!("{} res.", reseaux.len());
        Text::new(&total, Point::new(180, 19), MonoTextStyle::new(&FONT_6X10, WHITE))
            .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let style = MonoTextStyle::new(&FONT_6X10, WHITE);
        let style_dim = MonoTextStyle::new(&FONT_6X10, DIM);
        let mut y = 42i32;
        for ap in reseaux.iter().take(8) {
            // Ligne 1 : SSID + canal + chiffrement
            let txt = format!("{:<14.14} c{:<2} {}", ap.ssid.as_str(), ap.channel, auth_court(ap.auth_method));
            Text::new(&txt, Point::new(6, y), style)
                .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

            // Barres de signal a droite
            let n = barres(ap.signal_strength);
            let couleur = if n >= 3 { GREEN } else if n == 2 { ORANGE } else { RED };
            for b in 0..4u8 {
                let h = 3 + (b as i32) * 2;
                let bx = 205 + (b as i32) * 7;
                let by = y - h;
                let col = if b < n { couleur } else { GRAY };
                Rectangle::new(Point::new(bx, by), Size::new(5, h as u32))
                    .into_styled(PrimitiveStyleBuilder::new().fill_color(col).build())
                    .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }

            // Ligne 2 : BSSID complet (MAC de l AP)
            let m = ap.bssid;
            let mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}  {}dBm",
                m[0], m[1], m[2], m[3], m[4], m[5], ap.signal_strength);
            Text::new(&mac, Point::new(6, y + 11), style_dim)
                .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

            info!("  {} | {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} | canal {} | {} dBm | {:?}",
                ap.ssid.as_str(), m[0], m[1], m[2], m[3], m[4], m[5],
                ap.channel, ap.signal_strength, ap.auth_method);
            y += 24;
        }

        FreeRtos::delay_ms(5000);
    }
}

fn banner<D>(display: &mut D, msg: &str) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(msg, Point::new(40, 120), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}