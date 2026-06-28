use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::PinDriver;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::spi::{config::{Config, MODE_3}, Dma, SpiDeviceDriver, SpiDriver, SpiDriverConfig};
use esp_idf_svc::hal::units::FromValueType;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::nvs::EspDefaultNvsPartition;

use display_interface_spi::SPIInterface;
use mipidsi::{Builder, models::ST7789};
use mipidsi::options::ColorInversion;

use embedded_graphics::{
    mono_font::{ascii::FONT_10X20, MonoTextStyle},
    pixelcolor::{raw::RawU16, Rgb565},
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::{Alignment, Text, TextStyleBuilder},
};
use log::info;

use crate::logo;

// 0 = Scan reseaux, 1 = Point d'acces, 2 = BadUSB BLE. Change puis reflashe.
const DEMO_MODE: usize = 2;

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const BLACK: Rgb565 = Rgb565::BLACK;

const MAIN_MENU: &[&str] = &["NFC / RFID", "Sub-GHz 433", "WiFi Tools", "BadUSB BLE", "Settings"];
const WIFI_MENU: &[&str] = &["Scan reseaux", "Point d'acces", "Capture handshake", "Retour"];

fn item_y(i: usize) -> i32 {
    45 + (i as i32 * 36)
}

pub fn run(sys_loop: EspSystemEventLoop, nvs: EspDefaultNvsPartition) -> anyhow::Result<()> {
    info!("=== Axolotl Zero : demo simulee ===");

    let peripherals = Peripherals::take()?;

    let spi_driver = SpiDriver::new(
        peripherals.spi2,
        peripherals.pins.gpio12,
        peripherals.pins.gpio11,
        None::<esp_idf_svc::hal::gpio::AnyIOPin>,
        &SpiDriverConfig::new().dma(Dma::Auto(4096)),
    )?;
    let spi_device = SpiDeviceDriver::new(
        spi_driver,
        None::<esp_idf_svc::hal::gpio::AnyOutputPin>,
        &Config::new().baudrate(40_000_000_u32.Hz()).data_mode(MODE_3),
    )?;
    let dc = PinDriver::output(peripherals.pins.gpio9)?;
    let rst = PinDriver::output(peripherals.pins.gpio10)?;
    let di = SPIInterface::new(spi_device, dc);

    let mut display = Builder::new(ST7789, di)
        .display_size(240, 240)
        .invert_colors(ColorInversion::Inverted)
        .reset_pin(rst)
        .init(&mut FreeRtos)
        .map_err(|e| anyhow::anyhow!("init ecran: {:?}", e))?;

    // -- Splash logo --
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let logo_w = logo::LOGO_WIDTH as usize;
    let target_w = (logo_w * 2) as u16;
    let target_h = (logo::LOGO_HEIGHT as usize * 2) as u16;
    let pixel_iter = (0..target_h).flat_map(|y| {
        let lw = logo_w;
        (0..target_w).map(move |x| {
            let idx = (y / 2) as usize * lw + (x / 2) as usize;
            Rgb565::from(RawU16::new(logo::LOGO_DATA.get(idx).copied().unwrap_or(0)))
        })
    });
    display
        .set_pixels(0, 0, target_w - 1, target_h - 1, pixel_iter)
        .map_err(|e| anyhow::anyhow!("Splash: {:?}", e))?;
    FreeRtos::delay_ms(2000);

    if DEMO_MODE == 2 {
        // -- Navigation simulee : menu principal -> BadUSB BLE (index 3) --
        draw_menu(&mut display, "AXOLOTL ZERO", MAIN_MENU, 0)?;
        FreeRtos::delay_ms(1200);
        let mut sel = 0usize;
        while sel < 3 {
            sel += 1;
            FreeRtos::delay_ms(700);
            draw_menu(&mut display, "AXOLOTL ZERO", MAIN_MENU, sel)?;
        }
        FreeRtos::delay_ms(900);

        // -- Ecran de lancement du payload --
        draw_message(&mut display, "BADUSB BLE", "Lancement du", "payload...")?;
        FreeRtos::delay_ms(1500);
        draw_message(&mut display, "BADUSB BLE", "Appairez", "Axolotl Keyboard")?;

        // -- Lancement du BadUSB (BLE demarre ici, pas de WiFi : pas de conflit radio) --
        let keyboard = crate::badusb::make_keyboard()?;
        crate::badusb::run_payload(keyboard);
        return Ok(());
    }

    // -- Navigation simulee : menu principal -> WiFi Tools (index 2) --
    draw_menu(&mut display, "AXOLOTL ZERO", MAIN_MENU, 0)?;
    FreeRtos::delay_ms(1200);
    let mut sel = 0usize;
    while sel < 2 {
        sel += 1;
        FreeRtos::delay_ms(700);
        draw_menu(&mut display, "AXOLOTL ZERO", MAIN_MENU, sel)?;
    }
    FreeRtos::delay_ms(900);

    // -- Sous-menu WiFi --
    draw_menu(&mut display, "WIFI TOOLS", WIFI_MENU, 0)?;
    FreeRtos::delay_ms(1200);
    let mut sel = 0usize;
    let cible = if DEMO_MODE == 3 { 2 } else { DEMO_MODE };
    while sel < cible {
        sel += 1;
        FreeRtos::delay_ms(700);
        draw_menu(&mut display, "WIFI TOOLS", WIFI_MENU, sel)?;
    }
    FreeRtos::delay_ms(900);

    match DEMO_MODE {
        0 => crate::wifi_scan::run(peripherals.modem, sys_loop, nvs, &mut display)?,
        1 => crate::wifi_ap::run(peripherals.modem, sys_loop, nvs, &mut display)?,
        3 => crate::wifi_sniff::run(peripherals.modem, sys_loop, nvs, &mut display)?,
        _ => {}
    }

    loop {
        FreeRtos::delay_ms(1000);
    }
}

fn draw_message<D>(display: &mut D, title: &str, line1: &str, line2: &str) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(title, Point::new(120, 22), MonoTextStyle::new(&FONT_10X20, ORANGE), centered)
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(line1, Point::new(120, 110), MonoTextStyle::new(&FONT_10X20, WHITE), centered)
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(line2, Point::new(120, 140), MonoTextStyle::new(&FONT_10X20, WHITE), centered)
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn draw_menu<D>(display: &mut D, title: &str, items: &[&str], selected: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(title, Point::new(120, 22), MonoTextStyle::new(&FONT_10X20, ORANGE), centered)
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    for (i, it) in items.iter().enumerate() {
        let y = item_y(i);
        let (bg, txt) = if i == selected { (ORANGE, BLACK) } else { (BG, WHITE) };
        Rectangle::new(Point::new(10, y), Size::new(220, 28))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(bg).build())
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new(it, Point::new(20, y + 20), MonoTextStyle::new(&FONT_10X20, txt))
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }
    Ok(())
}