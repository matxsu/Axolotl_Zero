use display_interface_spi::SPIInterface;
use embedded_graphics::{
    mono_font::{
        ascii::{FONT_10X20, FONT_6X10},
        MonoTextStyle,
    },
    pixelcolor::{raw::RawU16, Rgb565},
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::{Alignment, Text, TextStyleBuilder},
};
use esp_idf_hal::{
    delay::FreeRtos,
    gpio::{AnyOutputPin, PinDriver, Pull},
    i2c::{I2cConfig, I2cDriver},
    spi::{
        config::{Config, MODE_3},
        SpiDeviceDriver, SpiDriver, SpiDriverConfig,
    },
    units::FromValueType,
};
use esp_idf_svc::sys::link_patches;
use mipidsi::{models::ST7789, Builder};

mod logo;
mod nfc;
mod storage;

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::WHITE;
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const BLACK: Rgb565 = Rgb565::BLACK;
const GREEN: Rgb565 = Rgb565::new(0, 40, 0);

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

    // ── SPI2 + Display ────────────────────────────────────────────────────
    let spi2 = SpiDriver::new(
        peripherals.spi2,
        peripherals.pins.gpio12,
        peripherals.pins.gpio11,
        None::<esp_idf_hal::gpio::AnyIOPin>,
        &SpiDriverConfig::new(),
    )?;
    let spi_device = SpiDeviceDriver::new(
        spi2,
        Some(peripherals.pins.gpio8),
        &Config::new()
            .baudrate(40_000_000_u32.Hz())
            .data_mode(MODE_3),
    )?;
    let dc = PinDriver::output(peripherals.pins.gpio9)?;
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

    // ── I2C + PN532 ───────────────────────────────────────────────────────
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio3,
        peripherals.pins.gpio4,
        &I2cConfig::new().baudrate(100_000_u32.Hz()),
    )?;
    let mut pn532 = nfc::Pn532::new(i2c)?;

    // ── SPI3 + SD card ────────────────────────────────────────────────────
    // SPI3 utilise les mêmes pins physiques que SPI2 mais bus logique séparé
    let spi3 = SpiDriver::new(
        peripherals.spi3,
        peripherals.pins.gpio12,       // SCK  (même fil)
        peripherals.pins.gpio11,       // MOSI (même fil)
        Some(peripherals.pins.gpio13), // MISO
        &SpiDriverConfig::new(),
    )?;
    let sd = match storage::SdStorage::new(spi3, peripherals.pins.gpio6.into()) {
        Ok(s) => {
            log::info!("SD: OK");
            Some(s)
        }
        Err(e) => {
            log::warn!("SD: non disponible: {:?}", e);
            None
        }
    };

    // ── Joystick ──────────────────────────────────────────────────────────
    let btn_up = PinDriver::input(peripherals.pins.gpio15, Pull::Up)?;
    let btn_dwn = PinDriver::input(peripherals.pins.gpio16, Pull::Up)?;
    let btn_lft = PinDriver::input(peripherals.pins.gpio17, Pull::Up)?;
    let btn_rht = PinDriver::input(peripherals.pins.gpio18, Pull::Up)?;
    let btn_mid = PinDriver::input(peripherals.pins.gpio21, Pull::Up)?;

    // ── Splash ────────────────────────────────────────────────────────────
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let logo_w = logo::LOGO_WIDTH as usize;
    let logo_h = logo::LOGO_HEIGHT as usize;
    let target_w = (logo_w * 2) as u16;
    let target_h = (logo_h * 2) as u16;
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
    log::info!("Splash OK ({}x{})", target_w, target_h);
    FreeRtos::delay_ms(1000);

    // ── Menu ──────────────────────────────────────────────────────────────
    let mut selected: usize = 0;
    draw_menu_full(&mut display, selected)?;

    loop {
        if btn_up.is_low() {
            let prev = selected;
            selected = if selected == 0 {
                MENU_ITEMS.len() - 1
            } else {
                selected - 1
            };
            draw_menu_item(&mut display, prev, false)?;
            draw_menu_item(&mut display, selected, true)?;
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if btn_dwn.is_low() {
            let prev = selected;
            selected = (selected + 1) % MENU_ITEMS.len();
            draw_menu_item(&mut display, prev, false)?;
            draw_menu_item(&mut display, selected, true)?;
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if btn_lft.is_low() {
            if selected != 0 {
                let prev = selected;
                selected = 0;
                draw_menu_item(&mut display, prev, false)?;
                draw_menu_item(&mut display, selected, true)?;
            }
            while btn_lft.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if btn_rht.is_low() {
            if selected != MENU_ITEMS.len() - 1 {
                let prev = selected;
                selected = MENU_ITEMS.len() - 1;
                draw_menu_item(&mut display, prev, false)?;
                draw_menu_item(&mut display, selected, true)?;
            }
            while btn_rht.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            match selected {
                0 => run_nfc_scan(&mut display, &mut pn532, &sd, &btn_mid, &btn_lft)?,
                3 => run_storage_info(&mut display, &sd, &btn_mid, &btn_lft)?,
                _ => {
                    draw_selected(&mut display, selected)?;
                    loop {
                        if btn_mid.is_low()
                            || btn_up.is_low()
                            || btn_dwn.is_low()
                            || btn_lft.is_low()
                            || btn_rht.is_low()
                        {
                            break;
                        }
                        FreeRtos::delay_ms(20);
                    }
                }
            }
            draw_menu_full(&mut display, selected)?;
            while btn_mid.is_low() || btn_up.is_low() || btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
        }
        FreeRtos::delay_ms(20);
    }
}

// ── NFC scan ───────────────────────────────────────────────────────────────

fn run_nfc_scan<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    sd: &Option<storage::SdStorage>,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_screen(display, None)?;
    loop {
        if btn_lft.is_low() {
            break;
        }
        match pn532.read_uid() {
            Ok(Some(uid)) => {
                let hex = uid.to_hex();
                log::info!("NFC UID: {}", hex.as_str());
                draw_nfc_screen(display, Some(&hex))?;
                // MID = dump MIFARE
                let mut waited = 0u32;
                loop {
                    if btn_lft.is_low() {
                        break;
                    }
                    if btn_mid.is_low() {
                        while btn_mid.is_low() {
                            FreeRtos::delay_ms(10);
                        }
                        draw_nfc_status(display, "Dump en cours...")?;
                        match pn532.mifare_dump(&uid) {
                            Ok(dump) => {
                                dump.print_log();
                                // Sauvegarder sur SD si disponible
                                if let Some(sd) = sd {
                                    let filename =
                                        format!("/NFC/dumps/{}.txt", hex.as_str().replace(':', ""));
                                    let mut data = format!("UID: {}\n\n", hex.as_str());
                                    for block in 0..64usize {
                                        if dump.readable[block] {
                                            let d = &dump.blocks[block];
                                            data.push_str(&format!(
                                                "Bloc {:02}: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}\n",
                                                block,
                                                d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],
                                                d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15]
                                            ));
                                        } else {
                                            data.push_str(&format!(
                                                "Bloc {:02}: -- non lisible --\n",
                                                block
                                            ));
                                        }
                                    }
                                    match sd.write_file(&filename, data.as_bytes()) {
                                        Ok(_) => draw_nfc_status(display, "Dump sauvegarde SD!")?,
                                        Err(e) => {
                                            log::warn!("SD write err: {:?}", e);
                                            draw_nfc_status(display, "Dump OK (SD err)")?;
                                        }
                                    }
                                } else {
                                    draw_nfc_status(display, "Dump OK! Voir logs")?;
                                }
                            }
                            Err(e) => {
                                log::warn!("Dump err: {:?}", e);
                                draw_nfc_status(display, "Dump echoue")?;
                            }
                        }
                        FreeRtos::delay_ms(2000);
                        draw_nfc_screen(display, Some(&hex))?;
                        break;
                    }
                    FreeRtos::delay_ms(20);
                    waited += 20;
                    if waited > 5000 {
                        break;
                    } // retour scan après 5s
                }
                if btn_lft.is_low() {
                    break;
                }
                draw_nfc_screen(display, None)?;
            }
            Ok(None) => {}
            Err(_) => {}
        }
        FreeRtos::delay_ms(300);
    }
    Ok(())
}

// ── Storage info ───────────────────────────────────────────────────────────

fn run_storage_info<D>(
    display: &mut D,
    sd: &Option<storage::SdStorage>,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        "Storage",
        Point::new(120, 40),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let status = if sd.is_some() {
        "SD card: OK"
    } else {
        "SD card: absent"
    };
    Text::with_text_style(
        status,
        Point::new(120, 100),
        MonoTextStyle::new(&FONT_10X20, if sd.is_some() { GREEN } else { GRAY }),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    if let Some(sd) = sd {
        if let Ok(files) = sd.list_dir("/NFC/dumps") {
            let count = format!("{} dump(s)", files.len());
            Text::with_text_style(
                &count,
                Point::new(120, 130),
                MonoTextStyle::new(&FONT_6X10, WHITE),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    Text::with_text_style(
        "LFT: retour",
        Point::new(120, 220),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    loop {
        if btn_mid.is_low() || btn_lft.is_low() {
            break;
        }
        FreeRtos::delay_ms(20);
    }
    Ok(())
}

// ── Draw helpers ───────────────────────────────────────────────────────────

fn draw_nfc_screen<D>(display: &mut D, uid: Option<&heapless::String<32>>) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        "NFC / RFID",
        Point::new(120, 40),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    match uid {
        Some(hex) => {
            Text::with_text_style(
                "Carte detectee!",
                Point::new(120, 100),
                MonoTextStyle::new(&FONT_10X20, GREEN),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Text::with_text_style(
                "UID:",
                Point::new(120, 130),
                MonoTextStyle::new(&FONT_6X10, GRAY),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Text::with_text_style(
                hex.as_str(),
                Point::new(120, 155),
                MonoTextStyle::new(&FONT_10X20, WHITE),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Text::with_text_style(
                "MID: dump  LFT: retour",
                Point::new(120, 220),
                MonoTextStyle::new(&FONT_6X10, GRAY),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
        None => {
            Text::with_text_style(
                "En attente...",
                Point::new(120, 110),
                MonoTextStyle::new(&FONT_10X20, GRAY),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Text::with_text_style(
                "Approche une carte NFC",
                Point::new(120, 140),
                MonoTextStyle::new(&FONT_6X10, GRAY),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            Text::with_text_style(
                "LFT: retour",
                Point::new(120, 220),
                MonoTextStyle::new(&FONT_6X10, GRAY),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }
    Ok(())
}

fn draw_nfc_status<D>(display: &mut D, msg: &str) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        msg,
        Point::new(120, 120),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn draw_menu_full<D>(display: &mut D, selected: usize) -> anyhow::Result<()>
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
    Text::with_text_style(
        "AXOLOTL ZERO",
        Point::new(120, 22),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    for i in 0..MENU_ITEMS.len() {
        draw_menu_item(display, i, i == selected)?;
    }
    Ok(())
}

fn draw_menu_item<D>(display: &mut D, i: usize, selected: bool) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let y = item_y(i);
    let (bg_color, txt_color) = if selected {
        (ORANGE, BLACK)
    } else {
        (BG, WHITE)
    };
    Rectangle::new(Point::new(10, y), Size::new(220, 28))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(bg_color).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::new(
        MENU_ITEMS[i],
        Point::new(20, y + 20),
        MonoTextStyle::new(&FONT_10X20, txt_color),
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn draw_selected<D>(display: &mut D, selected: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        MENU_ITEMS[selected],
        Point::new(120, 100),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(
        "[ appuie pour revenir ]",
        Point::new(120, 140),
        MonoTextStyle::new(&FONT_6X10, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}
