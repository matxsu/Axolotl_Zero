//! Scan des réseaux Wi-Fi 2.4 GHz (mode station).
//!
//! Porté depuis `feature/wifi_attacks:src/wifi_scan.rs`. Adaptations pour
//! l'intégration au menu de `main.rs` :
//!   - `modem` emprunté (`impl Peripheral`) pour être réutilisable entre écrans ;
//!   - bouton retour (`back`) → sortie propre → le modem est rendu à l'appelant.

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use esp_idf_svc::hal::modem::WifiModemPeripheral;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};
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
    if rssi >= -50 {
        4
    } else if rssi >= -60 {
        3
    } else if rssi >= -70 {
        2
    } else {
        1
    }
}

/// Scanne en boucle et affiche les réseaux. `back` (bouton gauche) sort de
/// l'écran ; le `modem` emprunté est alors relâché pour l'appelant.
pub fn run<D>(
    modem: impl WifiModemPeripheral,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    display: &mut D,
    back: &PinDriver<'_, Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    info!("===== WIFI · SCAN RESEAUX =====");
    banner(display, "Scan en cours...")?;
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;
    info!("WiFi demarre en mode station");

    loop {
        if back.is_low() {
            return Ok(());
        }
        info!("--- Nouveau scan ---");
        let reseaux = wifi.scan()?;
        info!("{} reseaux trouves", reseaux.len());

        display.clear(BG).map_err(crate::anyhow_dbg)?;
        Rectangle::new(Point::new(0, 0), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        Text::new("Scan WiFi", Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        let total = format!("{} res.", reseaux.len());
        Text::new(&total, Point::new(180, 19), MonoTextStyle::new(&FONT_6X10, WHITE))
            .draw(display)
            .map_err(crate::anyhow_dbg)?;

        let style = MonoTextStyle::new(&FONT_6X10, WHITE);
        let style_dim = MonoTextStyle::new(&FONT_6X10, DIM);
        let mut y = 42i32;
        for ap in reseaux.iter().take(8) {
            // Ligne 1 : SSID + canal + chiffrement
            let txt = format!("{:<14.14} c{:<2} {}", ap.ssid.as_str(), ap.channel, auth_court(ap.auth_method));
            Text::new(&txt, Point::new(6, y), style)
                .draw(display)
                .map_err(crate::anyhow_dbg)?;

            // Barres de signal a droite
            let n = barres(ap.signal_strength);
            let couleur = if n >= 3 {
                GREEN
            } else if n == 2 {
                ORANGE
            } else {
                RED
            };
            for b in 0..4u8 {
                let h = 3 + (b as i32) * 2;
                let bx = 205 + (b as i32) * 7;
                let by = y - h;
                let col = if b < n { couleur } else { GRAY };
                Rectangle::new(Point::new(bx, by), Size::new(5, h as u32))
                    .into_styled(PrimitiveStyleBuilder::new().fill_color(col).build())
                    .draw(display)
                    .map_err(crate::anyhow_dbg)?;
            }

            // Ligne 2 : BSSID complet (MAC de l AP)
            let m = ap.bssid;
            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}  {}dBm",
                m[0], m[1], m[2], m[3], m[4], m[5], ap.signal_strength
            );
            Text::new(&mac, Point::new(6, y + 11), style_dim)
                .draw(display)
                .map_err(crate::anyhow_dbg)?;

            info!(
                "  {} | {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} | canal {} | {} dBm | {:?}",
                ap.ssid.as_str(), m[0], m[1], m[2], m[3], m[4], m[5], ap.channel, ap.signal_strength, ap.auth_method
            );
            y += 24;
        }

        // Rafraîchit toutes les ~5 s, mais reste réactif au bouton retour.
        for _ in 0..50 {
            if back.is_low() {
                return Ok(());
            }
            FreeRtos::delay_ms(100);
        }
    }
}

fn banner<D>(display: &mut D, msg: &str) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(crate::anyhow_dbg)?;
    Text::new(msg, Point::new(40, 120), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
    Ok(())
}

/// Réseau choisi via [`pick`], transmis aux outils qui ciblent un AP précis
/// (evil-twin qui clone le SSID, sniff qui vise un canal).
#[derive(Clone)]
pub struct ApChoice {
    pub ssid: String,
    pub channel: u8,
}

/// Scanne une fois puis affiche une liste **sélectionnable** de réseaux.
/// UP/DOWN naviguent, MID valide, `back` (gauche) annule.
/// Renvoie le réseau choisi, ou `None` si l'utilisateur annule.
#[allow(clippy::too_many_arguments)]
pub fn pick<D>(
    modem: impl WifiModemPeripheral,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    display: &mut D,
    btn_up: &PinDriver<'_, Input>,
    btn_dwn: &PinDriver<'_, Input>,
    btn_mid: &PinDriver<'_, Input>,
    back: &PinDriver<'_, Input>,
) -> anyhow::Result<Option<ApChoice>>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    info!("=== Selection reseau (pick) ===");
    banner(display, "Scan en cours...")?;
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;

    // Scan unique → liste figée à naviguer (pas de re-scan pendant la sélection).
    let reseaux = wifi.scan()?;
    let choices: Vec<ApChoice> = reseaux
        .iter()
        .map(|ap| ApChoice {
            ssid: ap.ssid.as_str().to_string(),
            channel: ap.channel,
        })
        .collect();

    if choices.is_empty() {
        banner(display, "Aucun reseau trouve")?;
        // Attend le bouton retour pour ne pas revenir instantanément.
        while !back.is_low() {
            FreeRtos::delay_ms(50);
        }
        while back.is_low() {
            FreeRtos::delay_ms(10);
        }
        return Ok(None);
    }

    let mut sel = 0usize;
    draw_pick_list(display, &choices, sel)?;
    loop {
        if btn_up.is_low() {
            sel = if sel == 0 { choices.len() - 1 } else { sel - 1 };
            draw_pick_list(display, &choices, sel)?;
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if btn_dwn.is_low() {
            sel = (sel + 1) % choices.len();
            draw_pick_list(display, &choices, sel)?;
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if back.is_low() {
            while back.is_low() {
                FreeRtos::delay_ms(10);
            }
            return Ok(None);
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            let c = choices[sel].clone();
            info!("Reseau choisi : {} (canal {})", c.ssid, c.channel);
            return Ok(Some(c));
        }
        FreeRtos::delay_ms(20);
    }
}

/// Dessine la liste des réseaux avec fenêtre de défilement (8 lignes visibles).
fn draw_pick_list<D>(display: &mut D, choices: &[ApChoice], selected: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    const VISIBLE: usize = 8;
    display.clear(BG).map_err(crate::anyhow_dbg)?;
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
    let title = format!("CIBLE  {}/{}", selected + 1, choices.len());
    Text::new(&title, Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
        .draw(display)
        .map_err(crate::anyhow_dbg)?;

    // Fenêtre de défilement centrée autour de la sélection.
    let start = selected.saturating_sub(VISIBLE - 1).min(choices.len().saturating_sub(VISIBLE));
    let mut y = 44i32;
    for (i, c) in choices.iter().enumerate().skip(start).take(VISIBLE) {
        let is_sel = i == selected;
        if is_sel {
            Rectangle::new(Point::new(4, y - 10), Size::new(232, 22))
                .into_styled(PrimitiveStyleBuilder::new().fill_color(ORANGE).build())
                .draw(display)
                .map_err(crate::anyhow_dbg)?;
        }
        let fg = if is_sel { BG } else { WHITE };
        let line = format!("{:<18.18} c{}", c.ssid, c.channel);
        Text::new(&line, Point::new(8, y + 5), MonoTextStyle::new(&FONT_6X10, fg))
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        y += 24;
    }
    Ok(())
}
