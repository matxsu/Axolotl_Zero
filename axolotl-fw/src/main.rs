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
    gpio::{PinDriver, Pull},
    i2c::{I2cConfig, I2cDriver},
    spi::{
        config::{Config, MODE_3},
        Dma, SpiDeviceDriver, SpiDriver, SpiDriverConfig,
    },
    units::FromValueType,
};
use storage::SdWrite;
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

/// Cache des derniers dumps en RAM — permet de re-cloner après être revenu
/// au menu sans re-scanner la carte source. Reset à chaque reboot.
#[derive(Default)]
struct LastDumps {
    classic: Option<Box<nfc::MifareDump>>,
    ultralight: Option<Vec<u8>>,
}

fn item_y(i: usize) -> i32 {
    45 + (i as i32 * 36)
}

fn main() -> anyhow::Result<()> {
    link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    // Verbose sur sdspi/sdmmc pour debug — à retirer une fois SD fonctionnelle
    unsafe {
        use esp_idf_svc::sys::{esp_log_level_set, esp_log_level_t_ESP_LOG_VERBOSE};
        esp_log_level_set(b"sdspi_transaction\0".as_ptr() as _, esp_log_level_t_ESP_LOG_VERBOSE);
        esp_log_level_set(b"sdmmc_common\0".as_ptr() as _, esp_log_level_t_ESP_LOG_VERBOSE);
        esp_log_level_set(b"sdmmc_init\0".as_ptr() as _, esp_log_level_t_ESP_LOG_VERBOSE);
        esp_log_level_set(b"sdspi_host\0".as_ptr() as _, esp_log_level_t_ESP_LOG_VERBOSE);
    }

    log::info!("Axolotl Zero — booting...");

    let peripherals = esp_idf_hal::peripherals::Peripherals::take()?;

    // ── SPI2 (partagé display + SD card) ─────────────────────────────────
    // MOSI=11  SCK=12  MISO=13
    // spi_driver déclaré en premier : dropé en dernier (après tous ses emprunteurs).

    // DMA::Auto(4096) obligatoire : SD card transfère des blocs de 512 bytes,
    // impossible sans DMA (FIFO SPI limité à 64 bytes sans DMA).
    let spi_driver = SpiDriver::new(
        peripherals.spi2,
        peripherals.pins.gpio12,
        peripherals.pins.gpio11,
        Some(peripherals.pins.gpio13),
        &SpiDriverConfig::new().dma(Dma::Auto(4096)),
    )?;

    // Pull-up interne ~45 kΩ sur MISO (GPIO13) APRÈS spi_bus_initialize()
    // car l'init SPI reconfigure les pads GPIO et peut effacer les pull-ups.
    // Remplacer par un 10 kΩ externe sur le PCB pour une solution robuste.
    unsafe { esp_idf_svc::sys::gpio_pullup_en(13) };

    // ── SD card : CS=6 — initialisée EN PREMIER sur le bus (mode neutre) ──
    // Si la SD s'initialise après le display (MODE_3), le bus SPI reste en
    // MODE_3 et la SD (MODE_0) ne répond plus à ACMD41.
    // 200 ms power-up : SD a besoin de ≥74 cycles à 400 kHz après Vcc stable.
    FreeRtos::delay_ms(200);
    let sd: Option<storage::SdStorage<'_, &SpiDriver<'_>>> =
        match storage::SdStorage::new(&spi_driver, peripherals.pins.gpio6.into()) {
            Ok(s) => {
                log::info!("SD: prete");
                Some(s)
            }
            Err(e) => {
                log::warn!("SD init: {:?} — fonctionnement sans SD", e);
                None
            }
        };

    // ── Display : CS=8, MODE_3, 40 MHz (après SD pour éviter conflits mode) ──
    let spi_device = SpiDeviceDriver::new(
        &spi_driver,
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
    let mut last_dumps = LastDumps::default();
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
                0 => run_nfc_scan(
                    &mut display,
                    &mut pn532,
                    sd.as_ref().map(|s| s as &dyn SdWrite),
                    &mut last_dumps,
                    &btn_mid,
                    &btn_lft,
                    &btn_up,
                    &btn_dwn,
                )?,
                3 => run_storage_info(
                    &mut display,
                    sd.as_ref().map(|s| s as &dyn SdWrite),
                    &btn_mid,
                    &btn_lft,
                )?,
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
    sd: Option<&dyn SdWrite>,
    last_dumps: &mut LastDumps,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_screen_with_cache(
                display,
                None,
                None,
                last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
            )?;
    loop {
        if btn_lft.is_low() {
            break;
        }
        // UP = re-clone du dernier dump en RAM (classic en priorité)
        if btn_up.is_low() {
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
            if let Some(dump) = last_dumps.classic.as_ref() {
                run_nfc_clone(display, pn532, dump, btn_lft)?;
                draw_nfc_screen_with_cache(
                display,
                None,
                None,
                last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
            )?;
            } else if let Some(data) = last_dumps.ultralight.as_ref() {
                // .clone() pour libérer last_dumps qui est emprunté
                let data_owned = data.clone();
                run_nfc_ultralight_clone(display, pn532, &data_owned, btn_lft)?;
                draw_nfc_screen_with_cache(
                display,
                None,
                None,
                last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
            )?;
            } else {
                draw_nfc_status(display, "Aucun dump en RAM")?;
                FreeRtos::delay_ms(1500);
                draw_nfc_screen_with_cache(
                    display,
                    None,
                    None,
                    last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
                )?;
            }
            continue;
        }
        // DOWN = browse blocs du dernier dump classic en RAM
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            if let Some(dump) = last_dumps.classic.as_ref() {
                run_view_dump(display, dump, btn_up, btn_dwn, btn_lft)?;
                draw_nfc_screen_with_cache(
                    display,
                    None,
                    None,
                    last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
                )?;
            } else {
                draw_nfc_status(display, "Aucun dump Classic")?;
                FreeRtos::delay_ms(1500);
                draw_nfc_screen_with_cache(
                    display,
                    None,
                    None,
                    last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
                )?;
            }
            continue;
        }
        match pn532.read_uid() {
            Ok(Some(uid)) => {
                let hex = uid.to_hex();
                let ctype = uid.card_type();
                log::info!(
                    "NFC UID: {} SAK={:#04x} ATQA={:02X}{:02X} -> {}",
                    hex.as_str(),
                    uid.sak,
                    uid.atqa[1],
                    uid.atqa[0],
                    ctype
                );
                draw_nfc_screen(display, Some(&hex), Some(ctype))?;

                let mut waited = 0u32;
                loop {
                    if btn_lft.is_low() {
                        break;
                    }
                    if btn_mid.is_low() {
                        while btn_mid.is_low() {
                            FreeRtos::delay_ms(10);
                        }

                        if uid.is_mifare_classic() {
                            run_nfc_dump_classic(
                                display, pn532, &uid, &hex, sd, last_dumps,
                                btn_mid, btn_lft,
                            )?;
                        } else if uid.is_ultralight() {
                            run_nfc_ultralight(
                                display, pn532, &hex, sd, last_dumps,
                                btn_mid, btn_lft,
                            )?;
                        } else {
                            draw_nfc_status(display, "Type non supporte")?;
                            FreeRtos::delay_ms(2000);
                        }

                        draw_nfc_screen(display, Some(&hex), Some(ctype))?;
                        break;
                    }
                    FreeRtos::delay_ms(20);
                    waited += 20;
                    if waited > 5000 {
                        break;
                    }
                }
                if btn_lft.is_low() {
                    break;
                }
                draw_nfc_screen_with_cache(
                display,
                None,
                None,
                last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
            )?;
            }
            Ok(None) => {}
            Err(_) => {}
        }
        FreeRtos::delay_ms(300);
    }
    Ok(())
}

// ── MIFARE Classic dump + clone ────────────────────────────────────────────

fn run_nfc_dump_classic<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    uid: &nfc::NfcUid,
    hex: &heapless::String<32>,
    sd: Option<&dyn SdWrite>,
    last_dumps: &mut LastDumps,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    match pn532.mifare_dump(uid, |sector, total| {
        let _ = draw_dump_progress(display, sector, total);
    }) {
        Ok(dump) => {
            nfc::print_dump_log(&dump);
            let readable_count = dump.readable_count();
            let total = dump.total_blocks();
            if let Some(sd) = sd.as_ref() {
                let uid_str = hex.as_str().replace(':', "");
                let _ = sd.write_file(
                    &format!("/NFC/dumps/{}.mfd", uid_str),
                    &dump.to_mfd_bytes(),
                );
                let mut txt = format!("UID: {}\nType: {:?}\n\n", hex.as_str(), dump.card_type);
                for block in 0..total {
                    if dump.readable[block] {
                        let d = &dump.blocks[block];
                        txt.push_str(&format!(
                            "Bloc {:03}: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}\n",
                            block,
                            d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],
                            d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15]
                        ));
                    } else {
                        txt.push_str(&format!(
                            "Bloc {:03}: -- non lisible --\n",
                            block
                        ));
                    }
                }
                let _ = sd.write_file(
                    &format!("/NFC/dumps/{}.txt", uid_str),
                    txt.as_bytes(),
                );
            }
            let acl = dump.access_summary();
            draw_post_dump(display, readable_count, total, &acl)?;
            loop {
                if btn_lft.is_low() {
                    break;
                }
                if btn_mid.is_low() {
                    while btn_mid.is_low() {
                        FreeRtos::delay_ms(10);
                    }
                    run_nfc_clone(display, pn532, &dump, btn_lft)?;
                    break;
                }
                FreeRtos::delay_ms(20);
            }
            // Cache le dump en RAM pour permettre re-clone depuis le menu
            last_dumps.classic = Some(dump);
        }
        Err(e) => {
            log::warn!("Dump err: {:?}", e);
            draw_nfc_status(display, "Dump echoue")?;
            FreeRtos::delay_ms(2000);
        }
    }
    Ok(())
}

// ── Ultralight / NTAG read ─────────────────────────────────────────────────

fn run_nfc_ultralight<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    hex: &heapless::String<32>,
    sd: Option<&dyn SdWrite>,
    last_dumps: &mut LastDumps,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_status(display, "Lecture UL/NTAG...")?;
    let data = match pn532.ntag_read_full() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("UL read err: {:?}", e);
            draw_nfc_status(display, "Lecture echouee")?;
            FreeRtos::delay_ms(2000);
            return Ok(());
        }
    };

    let pages = data.len() / 4;
    log::info!("=== UL/NTAG Dump : {} pages ({} bytes) ===", pages, data.len());
    for page in 0..pages {
        let p = &data[page * 4..page * 4 + 4];
        log::info!(
            "Page {:03}: {:02X} {:02X} {:02X} {:02X}",
            page,
            p[0],
            p[1],
            p[2],
            p[3]
        );
    }

    if let Some(sd) = sd.as_ref() {
        let uid_str = hex.as_str().replace(':', "");
        let _ = sd.write_file(&format!("/NFC/dumps/{}.bin", uid_str), &data);
        let mut txt = format!(
            "UID: {}\nType: Ultralight/NTAG ({} pages, {} bytes)\n\n",
            hex.as_str(),
            pages,
            data.len()
        );
        for page in 0..pages {
            let p = &data[page * 4..page * 4 + 4];
            txt.push_str(&format!(
                "Page {:03}: {:02X} {:02X} {:02X} {:02X}\n",
                page, p[0], p[1], p[2], p[3]
            ));
        }
        let _ = sd.write_file(&format!("/NFC/dumps/{}.txt", uid_str), txt.as_bytes());
    }

    draw_post_ul_dump(display, pages)?;

    // Boucle MID=clone / LFT=retour
    loop {
        if btn_lft.is_low() {
            break;
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            run_nfc_ultralight_clone(display, pn532, &data, btn_lft)?;
            break;
        }
        FreeRtos::delay_ms(20);
    }

    last_dumps.ultralight = Some(data);
    Ok(())
}

// ── Ultralight clone (écriture vers carte cible UL/NTAG) ──────────────────

fn run_nfc_ultralight_clone<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    data: &[u8],
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_status(display, "Approche UL/NTAG cible...")?;

    let mut target = None;
    for _ in 0..150u32 {
        if btn_lft.is_low() {
            return Ok(());
        }
        if let Ok(Some(u)) = pn532.read_uid() {
            if u.is_ultralight() {
                target = Some(u);
                break;
            }
            draw_nfc_status(display, "Pas une UL/NTAG")?;
            FreeRtos::delay_ms(1000);
            draw_nfc_status(display, "Approche UL/NTAG cible...")?;
        }
        FreeRtos::delay_ms(200);
    }

    if target.is_none() {
        draw_nfc_status(display, "Timeout - pas de carte")?;
        FreeRtos::delay_ms(2000);
        return Ok(());
    }

    match pn532.ultralight_clone(data, |page, total| {
        let _ = draw_dump_progress(display, page, total);
    }) {
        Ok(n) => {
            let msg = format!("{} pages ecrites!", n);
            draw_nfc_status(display, &msg)?;
        }
        Err(e) => {
            log::warn!("UL clone err: {:?}", e);
            draw_nfc_status(display, "Clone UL echoue")?;
        }
    }
    FreeRtos::delay_ms(2000);
    Ok(())
}

// ── NFC clone ──────────────────────────────────────────────────────────────

fn run_nfc_clone<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    dump: &nfc::MifareDump,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_status(display, "Approche carte cible...")?;

    // Attente de la carte cible — 30s timeout
    let mut target_uid = None;
    for _ in 0..150u32 {
        if btn_lft.is_low() {
            return Ok(());
        }
        if let Ok(Some(u)) = pn532.read_uid() {
            target_uid = Some(u);
            break;
        }
        FreeRtos::delay_ms(200);
    }

    let tuid = match target_uid {
        Some(u) => u,
        None => {
            draw_nfc_status(display, "Timeout - pas de carte")?;
            FreeRtos::delay_ms(2000);
            return Ok(());
        }
    };

    match pn532.mifare_restore(&tuid, dump, |sector, total| {
        let _ = draw_dump_progress(display, sector, total);
    }) {
        Ok(n) => {
            let msg = format!("{} blocs ecrits!", n);
            draw_nfc_status(display, &msg)?;
        }
        Err(e) => {
            log::warn!("Restore err: {:?}", e);
            draw_nfc_status(display, "Clone echoue")?;
        }
    }
    FreeRtos::delay_ms(2000);
    Ok(())
}

// ── Storage info ───────────────────────────────────────────────────────────

// ── Dump browser (view blocks on screen) ───────────────────────────────────

fn run_view_dump<D>(
    display: &mut D,
    dump: &nfc::MifareDump,
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let total = dump.total_blocks();
    if total == 0 {
        return Ok(());
    }
    let mut current = 0usize;
    draw_dump_block(display, dump, current)?;
    loop {
        if btn_lft.is_low() {
            while btn_lft.is_low() {
                FreeRtos::delay_ms(10);
            }
            break;
        }
        if btn_up.is_low() {
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
            current = if current == 0 { total - 1 } else { current - 1 };
            draw_dump_block(display, dump, current)?;
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            current = (current + 1) % total;
            draw_dump_block(display, dump, current)?;
        }
        FreeRtos::delay_ms(30);
    }
    Ok(())
}

fn draw_dump_block<D>(
    display: &mut D,
    dump: &nfc::MifareDump,
    block: usize,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    Text::with_text_style(
        "DUMP VIEWER",
        Point::new(120, 22),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let title = format!("Bloc {:03} / {:03}", block, dump.total_blocks() - 1);
    Text::with_text_style(
        &title,
        Point::new(120, 55),
        MonoTextStyle::new(&FONT_10X20, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    if !dump.readable[block] {
        Text::with_text_style(
            "<non lisible>",
            Point::new(120, 120),
            MonoTextStyle::new(&FONT_10X20, GRAY),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    } else {
        let d = &dump.blocks[block];
        let line1 = format!(
            "{:02X} {:02X} {:02X} {:02X}  {:02X} {:02X} {:02X} {:02X}",
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        );
        let line2 = format!(
            "{:02X} {:02X} {:02X} {:02X}  {:02X} {:02X} {:02X} {:02X}",
            d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]
        );
        Text::with_text_style(
            &line1,
            Point::new(120, 100),
            MonoTextStyle::new(&FONT_6X10, WHITE),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::with_text_style(
            &line2,
            Point::new(120, 120),
            MonoTextStyle::new(&FONT_6X10, WHITE),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        // Représentation ASCII (caractères imprimables uniquement)
        let mut ascii = String::with_capacity(16);
        for &b in d.iter() {
            ascii.push(if (0x20..0x7F).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        Text::with_text_style(
            &ascii,
            Point::new(120, 150),
            MonoTextStyle::new(&FONT_10X20, ORANGE),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Text::with_text_style(
        "UP/DOWN: navigate",
        Point::new(120, 200),
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

    Ok(())
}

fn run_storage_info<D>(
    display: &mut D,
    sd: Option<&dyn SdWrite>,
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

    let status = if sd.is_some() { "SD card: OK" } else { "SD card: absent" };
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

fn draw_nfc_screen_with_cache<D>(
    display: &mut D,
    uid: Option<&heapless::String<32>>,
    card_type: Option<&str>,
    has_cached_dump: bool,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_screen(display, uid, card_type)?;
    if uid.is_none() && has_cached_dump {
        let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
        Text::with_text_style(
            "UP: re-clone  DOWN: view",
            Point::new(120, 200),
            MonoTextStyle::new(&FONT_6X10, ORANGE),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }
    Ok(())
}

fn draw_nfc_screen<D>(
    display: &mut D,
    uid: Option<&heapless::String<32>>,
    card_type: Option<&str>,
) -> anyhow::Result<()>
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
                Point::new(120, 80),
                MonoTextStyle::new(&FONT_10X20, GREEN),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            if let Some(t) = card_type {
                Text::with_text_style(
                    t,
                    Point::new(120, 105),
                    MonoTextStyle::new(&FONT_6X10, ORANGE),
                    centered,
                )
                .draw(display)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }
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
            let hint = match card_type {
                Some(t) if t.contains("Classic") => "MID: dump  LFT: retour",
                Some(_) => "MID: lire  LFT: retour",
                None => "LFT: retour",
            };
            Text::with_text_style(
                hint,
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

fn draw_post_dump<D>(
    display: &mut D,
    readable: usize,
    total: usize,
    acl: &axolotl_core::dump::AccessSummary,
) -> anyhow::Result<()>
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

    let acl_summary = format!(
        "ACL fact:{} cust:{} corr:{}",
        acl.factory, acl.custom, acl.corrupt
    );
    Text::with_text_style(
        &acl_summary,
        Point::new(120, 140),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let msg = format!("{}/{} blocs lus", readable, total);
    Text::with_text_style(
        &msg,
        Point::new(120, 100),
        MonoTextStyle::new(&FONT_10X20, if readable > 0 { GREEN } else { GRAY }),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::with_text_style(
        "clone: carte magic requise",
        Point::new(120, 180),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::with_text_style(
        "MID: cloner  LFT: retour",
        Point::new(120, 220),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Ok(())
}

fn draw_post_ul_dump<D>(display: &mut D, pages: usize) -> anyhow::Result<()>
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

    let msg = format!("{} pages lues", pages);
    Text::with_text_style(
        &msg,
        Point::new(120, 100),
        MonoTextStyle::new(&FONT_10X20, GREEN),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::with_text_style(
        "clone: NTAG/UL cible",
        Point::new(120, 180),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::with_text_style(
        "MID: cloner  LFT: retour",
        Point::new(120, 220),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Ok(())
}

fn draw_dump_progress<D>(display: &mut D, sector: u8, total: u8) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    Text::with_text_style(
        "Dump en cours...",
        Point::new(120, 80),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let msg = format!("Secteur {}/{}", sector + 1, total);
    Text::with_text_style(
        &msg,
        Point::new(120, 120),
        MonoTextStyle::new(&FONT_10X20, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Rectangle::new(Point::new(20, 150), Size::new(200, 14))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let t = total.max(1) as u32;
    let filled = ((sector as u32 + 1) * 200 / t).min(200);
    if filled > 0 {
        Rectangle::new(Point::new(20, 150), Size::new(filled, 14))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(ORANGE).build())
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
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
