use display_interface_spi::SPIInterface;
use embedded_graphics::{
    mono_font::{
        ascii::{FONT_10X20, FONT_6X10},
        MonoTextStyle,
    },
    pixelcolor::{raw::RawU16, Rgb565},
    prelude::*,
    primitives::{Rectangle, PrimitiveStyleBuilder},
    text::{Alignment, Text, TextStyleBuilder},
};
use esp_idf_hal::{
    delay::FreeRtos,
    gpio::{PinDriver, Pull},
    spi::{
        config::{Config, MODE_3},
        SpiDeviceDriver, SpiDriver, SpiDriverConfig,
    },
    units::FromValueType,
};
use esp_idf_svc::sys::link_patches;
use mipidsi::{models::ST7789, Builder};

mod logo;

const BG:     Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE:  Rgb565 = Rgb565::WHITE;
const GRAY:   Rgb565 = Rgb565::new(9, 22, 13);
const BLACK:  Rgb565 = Rgb565::BLACK;

const MENU_ITEMS: &[&str] = &[
    "NFC / RFID",
    "Sub-GHz 433",
    "WiFi Tools",
    "Storage",
    "Settings",
];

fn item_y(i: usize) -> i32 {
    45 + (i as i32 * 36)
}

fn main() -> anyhow::Result<()> {
    link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    log::info!("Axolotl Zero — booting...");

    let peripherals = esp_idf_hal::peripherals::Peripherals::take()?;

    let spi = SpiDriver::new(
        peripherals.spi2,
        peripherals.pins.gpio12,
        peripherals.pins.gpio11, 
        None::<esp_idf_hal::gpio::AnyIOPin>,
        &SpiDriverConfig::new(),
    )?;

    let spi_device = SpiDeviceDriver::new(
        spi,
        Some(peripherals.pins.gpio8),
        &Config::new()
            .baudrate(40_000_000_u32.Hz()) 
            .data_mode(MODE_3),
    )?;

    let dc  = PinDriver::output(peripherals.pins.gpio9)?;
    let rst = PinDriver::output(peripherals.pins.gpio10)?;
    let mut blk = PinDriver::output(peripherals.pins.gpio46)?;
    blk.set_high()?;

    let di = SPIInterface::new(spi_device, dc);
    let mut display = Builder::new(ST7789, di)
        .display_size(240, 240)
        .invert_colors(mipidsi::options::ColorInversion::Inverted)
        .reset_pin(rst)
        .init(&mut FreeRtos)
        .map_err(|e| anyhow::anyhow!("Display init: {:?}", e))?;

    let btn_up  = PinDriver::input(peripherals.pins.gpio15, Pull::Up)?;
    let btn_dwn = PinDriver::input(peripherals.pins.gpio16, Pull::Up)?;
    let btn_lft = PinDriver::input(peripherals.pins.gpio17, Pull::Up)?;
    let btn_rht = PinDriver::input(peripherals.pins.gpio18, Pull::Up)?;
    let btn_mid = PinDriver::input(peripherals.pins.gpio21, Pull::Up)?;

    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let logo_w = logo::LOGO_WIDTH as usize;
    let logo_h = logo::LOGO_HEIGHT as usize;
    
    let target_w = (logo_w * 2) as u16;
    let target_h = (logo_h * 2) as u16;

    let pixel_iter = (0..target_h).flat_map(|y| {
        let logo_w_fixed = logo_w;
        (0..target_w).map(move |x| {
            let lx = (x / 2) as usize;
            let ly = (y / 2) as usize;
            let idx = ly * logo_w_fixed + lx;
            let color_raw = logo::LOGO_DATA.get(idx).copied().unwrap_or(0x0000);
            Rgb565::from(RawU16::new(color_raw))
        })
    });

    display.set_pixels(0, 0, target_w - 1, target_h - 1, pixel_iter)
        .map_err(|e| anyhow::anyhow!("Splash draw error: {:?}", e))?;

    log::info!("Splash OK ({}x{})", target_w, target_h);
    FreeRtos::delay_ms(1000);

    let mut selected: usize = 0;
    draw_menu_full(&mut display, selected)?;

    loop {
        if btn_up.is_low() {
            let prev = selected;
            selected = if selected == 0 { MENU_ITEMS.len() - 1 } else { selected - 1 };
            draw_menu_item(&mut display, prev, false)?;
            draw_menu_item(&mut display, selected, true)?;
            while btn_up.is_low() { FreeRtos::delay_ms(10); }
        }

        if btn_dwn.is_low() {
            let prev = selected;
            selected = (selected + 1) % MENU_ITEMS.len();
            draw_menu_item(&mut display, prev, false)?;
            draw_menu_item(&mut display, selected, true)?;
            while btn_dwn.is_low() { FreeRtos::delay_ms(10); }
        }

        if btn_lft.is_low() {
            if selected != 0 {
                let prev = selected;
                selected = 0;
                draw_menu_item(&mut display, prev, false)?;
                draw_menu_item(&mut display, selected, true)?;
            }
            while btn_lft.is_low() { FreeRtos::delay_ms(10); }
        }

        if btn_rht.is_low() {
            if selected != MENU_ITEMS.len() - 1 {
                let prev = selected;
                selected = MENU_ITEMS.len() - 1;
                draw_menu_item(&mut display, prev, false)?;
                draw_menu_item(&mut display, selected, true)?;
            }
            while btn_rht.is_low() { FreeRtos::delay_ms(10); }
        }

        if btn_mid.is_low() {
            while btn_mid.is_low() { FreeRtos::delay_ms(10); }
            draw_selected(&mut display, selected)?;
            loop {
                if btn_mid.is_low() || btn_up.is_low() || btn_dwn.is_low() || btn_lft.is_low() || btn_rht.is_low() { 
                    break; 
                }
                FreeRtos::delay_ms(20);
            }
            draw_menu_full(&mut display, selected)?;
            while btn_mid.is_low() || btn_up.is_low() || btn_dwn.is_low() { FreeRtos::delay_ms(10); }
        }

        FreeRtos::delay_ms(20);
    }
}

fn draw_menu_full<D>(display: &mut D, selected: usize) -> anyhow::Result<()>
where D: DrawTarget<Color = Rgb565>, D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    
    let style = PrimitiveStyleBuilder::new().fill_color(GRAY).build();
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(style)
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        "AXOLOTL ZERO", Point::new(120, 22),
        MonoTextStyle::new(&FONT_10X20, ORANGE), centered,
    ).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    for i in 0..MENU_ITEMS.len() {
        draw_menu_item(display, i, i == selected)?;
    }
    Ok(())
}

fn draw_menu_item<D>(display: &mut D, i: usize, selected: bool) -> anyhow::Result<()>
where D: DrawTarget<Color = Rgb565>, D::Error: core::fmt::Debug,
{
    let y = item_y(i);
    let (bg_color, txt_color) = if selected { (ORANGE, BLACK) } else { (BG, WHITE) };

    Rectangle::new(Point::new(10, y), Size::new(220, 28))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(bg_color).build())
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::new(MENU_ITEMS[i], Point::new(20, y + 20), MonoTextStyle::new(&FONT_10X20, txt_color))
        .draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn draw_selected<D>(display: &mut D, selected: usize) -> anyhow::Result<()>
where D: DrawTarget<Color = Rgb565>, D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        MENU_ITEMS[selected], Point::new(120, 100),
        MonoTextStyle::new(&FONT_10X20, ORANGE), centered,
    ).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::with_text_style(
        "[ appuie pour revenir ]", Point::new(120, 140),
        MonoTextStyle::new(&FONT_6X10, WHITE), centered,
    ).draw(display).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}