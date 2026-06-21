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
    ledc::{config::TimerConfig, LedcDriver, LedcTimerDriver},
    spi::{
        config::{Config, MODE_3},
        Dma, SpiDeviceDriver, SpiDriver, SpiDriverConfig,
    },
    units::FromValueType,
};
use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition, sys::link_patches};
use mipidsi::{models::ST7789, Builder};
use storage::SdWrite;

mod logo;
mod nfc;
mod storage;
mod wifi;

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::WHITE;
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const BLACK: Rgb565 = Rgb565::BLACK;
const GREEN: Rgb565 = Rgb565::new(0, 40, 0);

const MENU_ITEMS: [&str; 4] = ["NFC / RFID", "Sub-GHz 433", "WiFi Tools", "Storage"];

/// Cache des derniers dumps en RAM — permet de re-cloner après être revenu
/// au menu sans re-scanner la carte source. Reset à chaque reboot.
#[derive(Default)]
struct LastDumps {
    classic: Option<Box<nfc::MifareDump>>,
    /// Clés trouvées au dump — nécessaires pour reconstruire les trailers au clone
    /// (le dump renvoie KeyA masqué à 00).
    classic_keys: Vec<nfc::attacks::SectorKey>,
    ultralight: Option<Vec<u8>>,
}

fn item_y(i: usize) -> i32 {
    45 + (i as i32 * 36)
}

fn main() -> anyhow::Result<()> {
    link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    // Le main task IDF a un stack par défaut trop petit pour la chaîne de
    // types génériques mipidsi + SPI + embedded-graphics.
    // On délègue tout à un thread Rust avec 64 KB de stack.
    std::thread::Builder::new()
        .stack_size(65536)
        .spawn(run_app)?
        .join()
        .map_err(|_| anyhow::anyhow!("app thread panic"))?
}

fn run_app() -> anyhow::Result<()> {
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

    // ── Flash interne FAT (fallback persistence quand SD absente) ─────────
    let internal_fs: Option<storage::InternalFs> = match storage::InternalFs::new() {
        Ok(fs) => Some(fs),
        Err(e) => {
            log::warn!("Flash interne: {:?} — persistence desactivee", e);
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
    let ledc_timer = LedcTimerDriver::new(
        peripherals.ledc.timer0,
        &TimerConfig::new().frequency(1000_u32.Hz()),
    )?;
    let mut backlight = LedcDriver::new(
        peripherals.ledc.channel0,
        ledc_timer,
        peripherals.pins.gpio46,
    )?;
    backlight.set_duty(backlight.get_max_duty())?;

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
        &I2cConfig::new()
            .baudrate(40_000_u32.Hz()) // On passe de 100 kHz à 40 kHz
            .sda_enable_pullup(true) // On force le pull-up interne
            .scl_enable_pullup(true), // On force le pull-up interne
    )?;
    let mut pn532 = nfc::Pn532::new(i2c)?;

    // ── WiFi AP + serveur HTTP (non-fatal : SD browser web) ──────────────────
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;
    let web_server = wifi::WebServer::start(peripherals.modem, sysloop, nvs)
        .map_err(|e| {
            log::warn!("WebServer: {:?} — mode sans wifi", e);
            e
        })
        .ok();
    let web_ip: Option<&str> = if web_server.is_some() {
        Some(wifi::AP_IP)
    } else {
        None
    };

    // ── Joystick ──────────────────────────────────────────────────────────
    let btn_up = PinDriver::input(peripherals.pins.gpio15, Pull::Up)?;
    let btn_dwn = PinDriver::input(peripherals.pins.gpio16, Pull::Up)?;
    let btn_lft = PinDriver::input(peripherals.pins.gpio17, Pull::Up)?;
    let btn_rht = PinDriver::input(peripherals.pins.gpio18, Pull::Up)?;
    // GPIO21 tiré à LOW en permanence (LED RGB interne ou court-circuit module) → GPIO14
    let btn_mid = PinDriver::input(peripherals.pins.gpio14, Pull::Up)?;

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

    // Front descendant pour MID : ne déclenche que sur transition HIGH→LOW.
    let mut mid_prev_low = btn_mid.is_low();
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
        let mid_cur_low = btn_mid.is_low();
        let mid_edge = mid_cur_low && !mid_prev_low;
        mid_prev_low = mid_cur_low;
        if mid_edge {
            // attend le relâchement, timeout 500ms au cas où bouton coincé
            let mut t = 0u32;
            while btn_mid.is_low() && t < 50 {
                FreeRtos::delay_ms(10);
                t += 1;
            }
            let storage: Option<&dyn SdWrite> = sd
                .as_ref()
                .map(|s| s as &dyn SdWrite)
                .or_else(|| internal_fs.as_ref().map(|f| f as &dyn SdWrite));

            match selected {
                0 => run_nfc_scan(
                    &mut display,
                    &mut pn532,
                    storage,
                    &mut last_dumps,
                    &btn_mid,
                    &btn_lft,
                    &btn_up,
                    &btn_dwn,
                    &btn_rht,
                )?,
                3 => run_storage_browser(
                    &mut display,
                    storage,
                    &btn_mid,
                    &btn_lft,
                    &btn_up,
                    &btn_dwn,
                    web_ip,
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
            let mut t = 0u32;
            while (btn_mid.is_low() || btn_up.is_low() || btn_dwn.is_low()) && t < 100 {
                FreeRtos::delay_ms(10);
                t += 1;
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
    btn_rht: &PinDriver<'_, esp_idf_hal::gpio::Input>,
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
        // RIGHT = menu des dumps sauvegardés (sélection → clone, sans re-scan)
        if btn_rht.is_low() {
            while btn_rht.is_low() {
                FreeRtos::delay_ms(10);
            }
            run_saved_dumps(display, pn532, sd, btn_up, btn_dwn, btn_mid, btn_lft)?;
            draw_nfc_screen_with_cache(
                display,
                None,
                None,
                last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
            )?;
            continue;
        }
        // UP = re-clone du dernier dump en RAM (classic en priorité)
        if btn_up.is_low() {
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
            if let Some(dump) = last_dumps.classic.as_ref() {
                run_nfc_clone(display, pn532, dump, &last_dumps.classic_keys, btn_lft)?;
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
        // DOWN = browse blocs du dernier dump en RAM (classic ou UL)
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            if let Some(dump) = last_dumps.classic.as_ref() {
                run_view_dump(display, dump, btn_up, btn_dwn, btn_lft)?;
            } else if let Some(data) = last_dumps.ultralight.as_ref() {
                let data_owned = data.clone();
                run_view_ul_dump(display, &data_owned, btn_up, btn_dwn, btn_lft)?;
            } else {
                draw_nfc_status(display, "Aucun dump en RAM")?;
                FreeRtos::delay_ms(1500);
            }
            draw_nfc_screen_with_cache(
                display,
                None,
                None,
                last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
            )?;
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
                                display, pn532, &uid, &hex, sd, last_dumps, btn_mid, btn_lft,
                                btn_up, btn_dwn,
                            )?;
                        } else if uid.is_ultralight() {
                            run_nfc_ultralight(
                                display, pn532, &hex, sd, last_dumps, btn_mid, btn_lft,
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
                // Reset toujours — le PN532 doit revenir en état propre pour le
                // prochain scan.
                pn532.reset_field();
                // LEFT ici signifiait "quitter cette carte", PAS "quitter le NFC".
                // On consomme l'appui et on retourne au scan : poser une nouvelle
                // carte la détecte directement. Pour sortir du NFC, ré-appuyer
                // LEFT sur l'écran d'attente (test en haut de boucle).
                while btn_lft.is_low() {
                    FreeRtos::delay_ms(10);
                }
                draw_nfc_screen_with_cache(
                    display,
                    None,
                    None,
                    last_dumps.classic.is_some() || last_dumps.ultralight.is_some(),
                )?;
            }
            Ok(_) => {}
            Err(e) => {
                // Erreur de comm (ex. "PN532 timeout") → re-init de récupération.
                // Si ce log apparait a chaque scan, reset_field est encore en cause.
                log::warn!("NFC scan err: {:?} — recover", e);
                pn532.recover();
                FreeRtos::delay_ms(200);
            }
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
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    match pn532.mifare_dump(uid, |sector, total| {
        let _ = draw_dump_progress(display, sector, total);
    }) {
        Ok((dump, found_keys)) => {
            nfc::print_dump_log(&dump);
            let readable_count = dump.readable_count();
            let total = dump.total_blocks();
            // Sauvegarde UNIQUEMENT les dumps complets (64/64) : un .mfd partiel
            // se recharge avec tous les blocs marqués lisibles (from_mfd_bytes)
            // → les zéros passeraient pour des vraies données au clone.
            let complete = readable_count == total;
            if complete {
                if let Some(sd) = sd.as_ref() {
                    let uid_str = hex.as_str().replace(':', "");
                    // .mfd AVEC les clés réinjectées dans les trailers → re-clonable
                    // depuis le fichier seul (menu RIGHT) sans re-scanner la carte.
                    match sd.write_file(
                        &format!("/NFC/dumps/{}.mfd", uid_str),
                        &nfc::attacks::dump_to_mfd_with_keys(&dump, &found_keys),
                    ) {
                        Ok(_) => log::info!("Dump 64/64 sauvegarde : {}.mfd", uid_str),
                        Err(e) => log::warn!("Sauvegarde .mfd KO: {:?}", e),
                    }
                    let mut txt = format!("UID: {}\nType: {:?}\n\n", hex.as_str(), dump.card_type);
                    for block in 0..total {
                        let d = &dump.blocks[block];
                        txt.push_str(&format!(
                            "Bloc {:03}: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}\n",
                            block,
                            d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],
                            d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15]
                        ));
                    }
                    let _ = sd.write_file(&format!("/NFC/dumps/{}.txt", uid_str), txt.as_bytes());
                }
            } else {
                log::info!(
                    "Dump partiel {}/{} — non sauvegarde (incomplet)",
                    readable_count,
                    total
                );
            }
            let acl = dump.access_summary();
            let can_clone = readable_count > 0;
            draw_post_dump_with_attack(display, readable_count, total, &acl, !can_clone)?;
            loop {
                if btn_lft.is_low() {
                    break;
                }
                if can_clone && btn_mid.is_low() {
                    while btn_mid.is_low() {
                        FreeRtos::delay_ms(10);
                    }
                    run_nfc_clone(display, pn532, &dump, &found_keys, btn_lft)?;
                    break;
                }
                // DOWN → sous-menu attaques
                if btn_dwn.is_low() {
                    while btn_dwn.is_low() {
                        FreeRtos::delay_ms(10);
                    }
                    run_nfc_attacks(
                        display, pn532, &found_keys, btn_up, btn_dwn, btn_mid, btn_lft,
                    )?;
                    draw_post_dump_with_attack(display, readable_count, total, &acl, !can_clone)?;
                }
                FreeRtos::delay_ms(20);
            }
            last_dumps.classic = Some(dump);
            last_dumps.classic_keys = found_keys;
        }
        Err(e) => {
            log::warn!("Dump err: {:?}", e);
            draw_nfc_status(display, "Dump echoue")?;
            FreeRtos::delay_ms(2000);
        }
    }
    Ok(())
}

// ── Sous-menu Attaques NFC ─────────────────────────────────────────────────

// Darkside / Nested / "Magic?" retirés : ces attaques crypto exigent un contrôle
// bit-timing que le PN532 (I²C) ne permet pas → un Proxmark3 est requis. Le clone
// teste déjà gen1a/gen2 tout seul (cf. clone_to_magic), donc plus besoin d'un test
// "Magic?" séparé. Reste le wipe gen1a (utile sur carte magic réinscriptible).
const ATTACK_ITEMS: &[&str; 2] = &["Remettre a blanc", "Retour"];

fn draw_attack_menu<D>(display: &mut D, selected: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Rectangle::new(Point::new(0, 0), Size::new(240, 30))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(
        "NFC ATTACK",
        Point::new(120, 22),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    for (i, label) in ATTACK_ITEMS.iter().enumerate() {
        let y = 40 + i as i32 * 48;
        let (bg, fg) = if i == selected {
            (ORANGE, BLACK)
        } else {
            (BG, WHITE)
        };
        Rectangle::new(Point::new(10, y), Size::new(220, 38))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(bg).build())
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new(
            label,
            Point::new(20, y + 26),
            MonoTextStyle::new(&FONT_10X20, fg),
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }
    Ok(())
}

fn run_nfc_attacks<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    last_keys: &[nfc::attacks::SectorKey],
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let mut sel = 0usize;
    draw_attack_menu(display, sel)?;

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
            if sel > 0 {
                sel -= 1;
            }
            draw_attack_menu(display, sel)?;
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            if sel < ATTACK_ITEMS.len() - 1 {
                sel += 1;
            }
            draw_attack_menu(display, sel)?;
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            match sel {
                0 => {
                    // Remet la carte magic à blanc (transport state). gen1a via
                    // backdoor, gen2/CUID via auth secteur par secteur.
                    draw_nfc_status(display, "Remise a blanc\nApproche magic...")?;
                    if !pn532.re_select() {
                        draw_nfc_status(display, "Carte absente")?;
                        FreeRtos::delay_ms(2000);
                        draw_attack_menu(display, sel)?;
                        continue;
                    }
                    let mut last_blk = 0u8;
                    let (written, total) = pn532.wipe_to_blank(last_keys, |blk, _status| {
                        last_blk = blk;
                    });
                    let msg = if total == 0 {
                        "Echec\nCarte non-magic ?".to_string()
                    } else if written == total {
                        format!("Carte vierge\n{}/{} blocs", written, total)
                    } else {
                        format!("Wipe partiel\n{}/{} blocs", written, total)
                    };
                    draw_nfc_status(display, &msg)?;
                    log::info!(
                        "wipe_to_blank: {}/{} blocs effacés (dernier={})",
                        written,
                        total,
                        last_blk
                    );
                    FreeRtos::delay_ms(3000);
                    draw_attack_menu(display, sel)?;
                }
                1 | _ => break,
            }
        }
        FreeRtos::delay_ms(20);
    }
    Ok(())
}

fn draw_post_dump_with_attack<D>(
    display: &mut D,
    readable: usize,
    total: usize,
    acl: &axolotl_core::dump::AccessSummary,
    show_attack_hint: bool,
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

    let msg = format!("{}/{} blocs lus", readable, total);
    Text::with_text_style(
        &msg,
        Point::new(120, 100),
        MonoTextStyle::new(&FONT_10X20, if readable > 0 { GREEN } else { GRAY }),
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

    if show_attack_hint {
        Text::with_text_style(
            "Dict echoue — cles inconnues",
            Point::new(120, 170),
            MonoTextStyle::new(&FONT_6X10, ORANGE),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::with_text_style(
            "DWN: Attaques crypto",
            Point::new(120, 220),
            MonoTextStyle::new(&FONT_6X10, GREEN),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    } else {
        Text::with_text_style(
            "MID: clone  DWN: attack",
            Point::new(120, 220),
            MonoTextStyle::new(&FONT_6X10, GRAY),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
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
    log::info!(
        "=== UL/NTAG Dump : {} pages ({} bytes) ===",
        pages,
        data.len()
    );
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
    keys: &[nfc::attacks::SectorKey],
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_nfc_status(display, "Approche carte magic\n(gen2/gen1a/CUID)...")?;

    // Attente de la carte cible — 30s timeout
    let mut found = false;
    for _ in 0..150u32 {
        if btn_lft.is_low() {
            return Ok(());
        }
        if let Ok(Some(u)) = pn532.read_uid() {
            if u.is_mifare_classic() {
                found = true;
                break;
            }
            draw_nfc_status(display, "Pas une MIFARE Classic")?;
            FreeRtos::delay_ms(1000);
            draw_nfc_status(display, "Approche carte magic\n(gen2/gen1a/CUID)...")?;
        }
        FreeRtos::delay_ms(200);
    }
    if !found {
        draw_nfc_status(display, "Timeout - pas de carte")?;
        FreeRtos::delay_ms(2000);
        return Ok(());
    }

    // Clone réversible (vraie KeyA + access bits transport FF0780).
    match pn532.clone_to_magic(dump, keys, true, |sector, total| {
        let _ = draw_dump_progress(display, sector, total);
    }) {
        Ok((n, block0)) => {
            // Read-back : UID réel de la carte clonée.
            let rb = pn532.read_uid().ok().flatten().map(|u| u.to_hex());
            let uid_line = rb
                .as_ref()
                .map(|h| h.as_str().to_string())
                .unwrap_or_else(|| "?".to_string());
            let msg = if block0 {
                format!("{} blocs ecrits\nUID clone -> {}", n, uid_line)
            } else {
                // Pas un échec : un lecteur VIGIK auth par KeyA+data, souvent
                // sans vérifier l'UID. La porte peut s'ouvrir quand même.
                format!(
                    "{} blocs ecrits\nUID non ecrit ({})\n-> teste sur la porte!",
                    n, uid_line
                )
            };
            draw_nfc_status(display, &msg)?;
            log::info!("Clone: {} blocs, bloc0={}, UID lu={}", n, block0, uid_line);
        }
        Err(e) => {
            log::warn!("Clone err: {:?}", e);
            // Garde-fou : cible non-magic → message explicite (rien n'a été
            // écrit, la carte n'est pas abîmée).
            let txt = e.to_string();
            if txt.contains("non-magic") {
                draw_nfc_status(
                    display,
                    "Cible non-magic\nbloc 0 verrouille\nclone annule (rien ecrit)",
                )?;
            } else {
                draw_nfc_status(display, "Clone echoue")?;
            }
        }
    }
    FreeRtos::delay_ms(4000);
    Ok(())
}

// ── Dumps sauvegardés : sélection → clone ────────────────────────────────────

/// Charge un .mfd depuis un chemin ABSOLU : infère le type carte d'après la
/// taille et reconstruit les clés depuis les trailers (cf. `dump_to_mfd_with_keys`).
fn load_dump_file(path: &str) -> Option<(nfc::MifareDump, Vec<nfc::attacks::SectorKey>)> {
    let data = std::fs::read(path).ok()?;
    let card_type = match data.len() {
        320 => nfc::ClassicType::Mini,
        1024 => nfc::ClassicType::Classic1K,
        4096 => nfc::ClassicType::Classic4K,
        _ => return None,
    };
    let dump = nfc::MifareDump::from_mfd_bytes(card_type, &data)?;
    let keys = nfc::attacks::keys_from_dump(&dump);
    Some((dump, keys))
}

/// Scanne les DEUX racines de stockage (`/sdcard` puis `/spiflash`) pour les
/// dumps `.mfd`. Un dump écrit sur la flash interne (SD absente au moment du
/// dump) reste ainsi visible quand la SD monte à un boot ultérieur — sinon le
/// menu liste la mauvaise racine et affiche "Aucun dump sauve".
///
/// Retourne (nom_affiché, chemin_absolu), dédupliqué par nom (SD prioritaire)
/// puis trié. L'extension est testée sans tenir compte de la casse : FAT 8.3
/// peut remonter `.MFD` en majuscules selon la config LFN.
fn collect_saved_dumps() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for root in ["/sdcard", "/spiflash"] {
        let dir = format!("{root}/NFC/dumps");
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.to_ascii_lowercase().ends_with(".mfd") {
                continue;
            }
            // Dédup par nom (insensible à la casse) : la 1ère racine (SD) gagne.
            if out.iter().any(|(n, _)| n.eq_ignore_ascii_case(&name)) {
                continue;
            }
            let path = format!("{dir}/{name}");
            out.push((name, path));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    log::info!(
        "collect_saved_dumps: {} dump(s) .mfd (scan /sdcard + /spiflash)",
        out.len()
    );
    out
}

/// Retire l'extension `.mfd` (quelle que soit la casse) pour l'affichage.
fn dump_stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if name[i..].eq_ignore_ascii_case(".mfd") => &name[..i],
        _ => name,
    }
}

/// Menu : liste les dumps complets sauvegardés et permet de les cloner sur une
/// carte magic sans re-scanner la carte source.
fn run_saved_dumps<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    sd: Option<&dyn SdWrite>,
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    if sd.is_none() {
        draw_nfc_status(display, "Pas de stockage")?;
        FreeRtos::delay_ms(1500);
        return Ok(());
    }

    // Scanne /sdcard ET /spiflash : un dump sauvé sur la flash interne reste
    // visible même quand la SD monte à un boot ultérieur (et inversement).
    let entries = collect_saved_dumps();
    if entries.is_empty() {
        draw_nfc_status(display, "Aucun dump sauve\n(dump 64/64 requis)")?;
        FreeRtos::delay_ms(2000);
        return Ok(());
    }
    let files: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();

    let mut sel = 0usize;
    draw_dump_list(display, &files, sel)?;
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
            sel = if sel == 0 { files.len() - 1 } else { sel - 1 };
            draw_dump_list(display, &files, sel)?;
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            sel = (sel + 1) % files.len();
            draw_dump_list(display, &files, sel)?;
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            match load_dump_file(&entries[sel].1) {
                Some((dump, keys)) => {
                    run_saved_dump_action(
                        display,
                        pn532,
                        &files[sel],
                        &dump,
                        &keys,
                        btn_up,
                        btn_dwn,
                        btn_mid,
                        btn_lft,
                    )?;
                }
                None => {
                    draw_nfc_status(display, "Lecture/format KO")?;
                    FreeRtos::delay_ms(1500);
                }
            }
            draw_dump_list(display, &files, sel)?;
        }
        FreeRtos::delay_ms(30);
    }
    Ok(())
}

/// Écran d'action sur un dump sélectionné : MID=cloner, DOWN=voir, LFT=retour.
fn run_saved_dump_action<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    name: &str,
    dump: &nfc::MifareDump,
    keys: &[nfc::attacks::SectorKey],
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    draw_saved_dump_info(display, name, dump, keys.len())?;
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
            run_emulate_dump(display, pn532, name, dump, keys)?;
            draw_saved_dump_info(display, name, dump, keys.len())?;
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            run_nfc_clone(display, pn532, dump, keys, btn_lft)?;
            draw_saved_dump_info(display, name, dump, keys.len())?;
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            run_view_dump(display, dump, btn_up, btn_dwn, btn_lft)?;
            draw_saved_dump_info(display, name, dump, keys.len())?;
        }
        FreeRtos::delay_ms(30);
    }
    Ok(())
}

fn run_emulate_dump<D>(
    display: &mut D,
    pn532: &mut nfc::Pn532,
    name: &str,
    dump: &nfc::MifareDump,
    keys: &[nfc::attacks::SectorKey],
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
    Text::with_text_style(
        "EMULATION",
        Point::new(120, 30),
        MonoTextStyle::new(&FONT_10X20, GREEN),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let stem = dump_stem(name);
    Text::with_text_style(
        stem,
        Point::new(120, 60),
        MonoTextStyle::new(&FONT_10X20, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    // L'émulation bloque sur TgInitAsTarget tant qu'aucun lecteur n'active la
    // cible : l'écran affiche la consigne pendant toute la fenêtre d'attente.
    let mut status_line = String::from("Approche lecteur...");
    let draw_status = |display: &mut D, line: &str| -> anyhow::Result<()> {
        // Efface la zone de status (y=90..115) et réaffiche
        Rectangle::new(Point::new(0, 85), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(BG).build())
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::with_text_style(
            line,
            Point::new(120, 105),
            MonoTextStyle::new(&FONT_6X10, ORANGE),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Ok(())
    };
    draw_status(display, &status_line)?;

    let result = pn532.emulate_mifare(dump, keys, |msg| {
        status_line = msg.to_string();
        // On ne peut pas appeler draw_status ici (borrow de display),
        // mais on log pour le monitor série.
        log::info!("emul: {}", msg);
    });

    // Affiche le résultat final
    let result_str = match result {
        nfc::EmulResult::Done => "Session terminee",
        nfc::EmulResult::Timeout => "Timeout (pas de lecteur)",
        nfc::EmulResult::Error(ref e) => e.as_str(),
    };
    draw_status(display, result_str)?;
    FreeRtos::delay_ms(2000);
    Ok(())
}

fn draw_dump_list<D>(display: &mut D, files: &[String], sel: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    Text::with_text_style(
        "DUMPS SAUVES",
        Point::new(120, 28),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    // Fenêtre glissante de 7 entrées autour de la sélection.
    const VISIBLE: usize = 7;
    let start = if sel >= VISIBLE { sel - VISIBLE + 1 } else { 0 };
    for (row, idx) in (start..files.len().min(start + VISIBLE)).enumerate() {
        let y = 60 + row as i32 * 22;
        let stem = dump_stem(&files[idx]);
        let (prefix, color) = if idx == sel {
            ("> ", GREEN)
        } else {
            ("  ", GRAY)
        };
        let line = format!("{}{}", prefix, stem);
        Text::with_text_style(
            &line,
            Point::new(120, y),
            MonoTextStyle::new(&FONT_10X20, color),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Text::with_text_style(
        "MID:ouvrir  UP/DN:nav  LFT:retour",
        Point::new(120, 228),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Ok(())
}

fn draw_saved_dump_info<D>(
    display: &mut D,
    name: &str,
    dump: &nfc::MifareDump,
    key_count: usize,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    Text::with_text_style(
        "DUMP",
        Point::new(120, 30),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let stem = dump_stem(name);
    Text::with_text_style(
        stem,
        Point::new(120, 70),
        MonoTextStyle::new(&FONT_10X20, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let info = format!("{:?}  {} blocs", dump.card_type, dump.total_blocks());
    Text::with_text_style(
        &info,
        Point::new(120, 105),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let keys_line = format!("{} cles dispo", key_count);
    Text::with_text_style(
        &keys_line,
        Point::new(120, 130),
        MonoTextStyle::new(&FONT_6X10, if key_count > 0 { GREEN } else { GRAY }),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Text::with_text_style(
        "UP: emuler badge",
        Point::new(120, 175),
        MonoTextStyle::new(&FONT_6X10, GREEN),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(
        "MID: cloner (carte magic)",
        Point::new(120, 195),
        MonoTextStyle::new(&FONT_6X10, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(
        "DOWN: voir blocs  LFT: retour",
        Point::new(120, 215),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
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

fn run_view_ul_dump<D>(
    display: &mut D,
    data: &[u8],
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let total = data.len() / 4;
    if total == 0 {
        return Ok(());
    }
    let mut current = 0usize;
    draw_ul_page(display, data, current, total)?;
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
            draw_ul_page(display, data, current, total)?;
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            current = (current + 1) % total;
            draw_ul_page(display, data, current, total)?;
        }
        FreeRtos::delay_ms(30);
    }
    Ok(())
}

fn draw_ul_page<D>(display: &mut D, data: &[u8], page: usize, total: usize) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    Text::with_text_style(
        "UL/NTAG VIEWER",
        Point::new(120, 22),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let title = format!("Page {:03} / {:03}", page, total - 1);
    Text::with_text_style(
        &title,
        Point::new(120, 55),
        MonoTextStyle::new(&FONT_10X20, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let off = page * 4;
    let d = data.get(off..off + 4).unwrap_or(&[0, 0, 0, 0]);
    let hex = format!("{:02X} {:02X} {:02X} {:02X}", d[0], d[1], d[2], d[3]);
    Text::with_text_style(
        &hex,
        Point::new(120, 110),
        MonoTextStyle::new(&FONT_10X20, WHITE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let mut ascii = String::with_capacity(4);
    for &b in d.iter() {
        ascii.push(if (0x20..0x7F).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    Text::with_text_style(
        &ascii,
        Point::new(120, 140),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

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

fn draw_dump_block<D>(display: &mut D, dump: &nfc::MifareDump, block: usize) -> anyhow::Result<()>
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

// ── Storage file browser ──────────────────────────────────────────────────

struct FsBrowserEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

fn list_fs_entries(path: &str) -> Vec<FsBrowserEntry> {
    let Ok(rd) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut entries: Vec<FsBrowserEntry> = rd
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let meta = e.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            FsBrowserEntry { name, is_dir, size }
        })
        .collect();
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    entries
}

const BROWSER_VISIBLE: usize = 8;

fn run_storage_browser<D>(
    display: &mut D,
    _sd: Option<&dyn SdWrite>,
    btn_mid: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    web_ip: Option<&str>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let root = if std::fs::metadata("/sdcard").is_ok() {
        "/sdcard"
    } else if std::fs::metadata("/spiflash").is_ok() {
        "/spiflash"
    } else {
        draw_storage_screen(display, &[], 0, 0, "no storage", web_ip)?;
        loop {
            if btn_lft.is_low() {
                while btn_lft.is_low() {
                    FreeRtos::delay_ms(10);
                }
                return Ok(());
            }
            FreeRtos::delay_ms(30);
        }
    };

    let mut path_stack: Vec<String> = vec![root.to_string()];
    let mut sel: usize = 0;
    let mut scroll: usize = 0;
    let mut entries = list_fs_entries(root);
    draw_storage_screen(display, &entries, sel, scroll, root, web_ip)?;

    loop {
        if btn_lft.is_low() {
            while btn_lft.is_low() {
                FreeRtos::delay_ms(10);
            }
            if path_stack.len() > 1 {
                path_stack.pop();
                sel = 0;
                scroll = 0;
                entries = list_fs_entries(path_stack.last().unwrap());
                draw_storage_screen(
                    display,
                    &entries,
                    sel,
                    scroll,
                    path_stack.last().unwrap(),
                    web_ip,
                )?;
            } else {
                break;
            }
        }
        if btn_up.is_low() {
            while btn_up.is_low() {
                FreeRtos::delay_ms(10);
            }
            if sel > 0 {
                sel -= 1;
                if sel < scroll {
                    scroll = sel;
                }
                draw_storage_screen(
                    display,
                    &entries,
                    sel,
                    scroll,
                    path_stack.last().unwrap(),
                    web_ip,
                )?;
            }
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            if !entries.is_empty() && sel + 1 < entries.len() {
                sel += 1;
                if sel >= scroll + BROWSER_VISIBLE {
                    scroll = sel + 1 - BROWSER_VISIBLE;
                }
                draw_storage_screen(
                    display,
                    &entries,
                    sel,
                    scroll,
                    path_stack.last().unwrap(),
                    web_ip,
                )?;
            }
        }
        if btn_mid.is_low() {
            while btn_mid.is_low() {
                FreeRtos::delay_ms(10);
            }
            if let Some(entry) = entries.get(sel) {
                let full = format!("{}/{}", path_stack.last().unwrap(), entry.name);
                if entry.is_dir {
                    path_stack.push(full);
                    sel = 0;
                    scroll = 0;
                    entries = list_fs_entries(path_stack.last().unwrap());
                    draw_storage_screen(
                        display,
                        &entries,
                        sel,
                        scroll,
                        path_stack.last().unwrap(),
                        web_ip,
                    )?;
                } else {
                    open_storage_file(display, &full, &entry.name, btn_up, btn_dwn, btn_lft)?;
                    draw_storage_screen(
                        display,
                        &entries,
                        sel,
                        scroll,
                        path_stack.last().unwrap(),
                        web_ip,
                    )?;
                }
            }
        }
        FreeRtos::delay_ms(30);
    }
    Ok(())
}

fn open_storage_file<D>(
    display: &mut D,
    full_path: &str,
    name: &str,
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    let data = match std::fs::read(full_path) {
        Ok(d) => d,
        Err(e) => {
            display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
            let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();
            let msg = format!("Erreur: {}", e);
            Text::with_text_style(
                &msg,
                Point::new(120, 120),
                MonoTextStyle::new(&FONT_6X10, Rgb565::RED),
                centered,
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            FreeRtos::delay_ms(2000);
            return Ok(());
        }
    };

    if name.to_ascii_lowercase().ends_with(".mfd") {
        let dump_opt = match data.len() {
            1024 => nfc::MifareDump::from_mfd_bytes(nfc::ClassicType::Classic1K, &data),
            4096 => nfc::MifareDump::from_mfd_bytes(nfc::ClassicType::Classic4K, &data),
            320 => nfc::MifareDump::from_mfd_bytes(nfc::ClassicType::Mini, &data),
            _ => None,
        };
        if let Some(dump) = dump_opt {
            return run_view_dump(display, &dump, btn_up, btn_dwn, btn_lft);
        }
    }
    run_view_raw_file(display, name, &data, btn_up, btn_dwn, btn_lft)
}

fn draw_storage_screen<D>(
    display: &mut D,
    entries: &[FsBrowserEntry],
    sel: usize,
    scroll: usize,
    path: &str,
    web_ip: Option<&str>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    Rectangle::new(Point::new(0, 0), Size::new(240, 28))
        .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    Text::with_text_style(
        "STORAGE",
        Point::new(120, 21),
        MonoTextStyle::new(&FONT_10X20, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    let display_path: String = if path.chars().count() > 32 {
        path.chars().skip(path.chars().count() - 32).collect()
    } else {
        path.to_string()
    };
    Text::with_text_style(
        &display_path,
        Point::new(120, 39),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    if entries.is_empty() {
        Text::with_text_style(
            "-- vide --",
            Point::new(120, 120),
            MonoTextStyle::new(&FONT_6X10, GRAY),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    } else {
        let count = BROWSER_VISIBLE.min(entries.len().saturating_sub(scroll));
        for i in 0..count {
            let idx = scroll + i;
            let entry = &entries[idx];
            let y = 52 + (i as i32) * 20;
            let is_sel = idx == sel;

            if is_sel {
                Rectangle::new(Point::new(0, y - 11), Size::new(240, 20))
                    .into_styled(PrimitiveStyleBuilder::new().fill_color(ORANGE).build())
                    .draw(display)
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }

            let txt_color = if is_sel {
                BLACK
            } else if entry.is_dir {
                ORANGE
            } else {
                WHITE
            };

            let short = if entry.name.len() > 19 {
                &entry.name[..19]
            } else {
                &entry.name
            };
            let line = if entry.is_dir {
                format!("> {}/", short)
            } else {
                let sz = if entry.size >= 1024 {
                    format!("{:.1}K", entry.size as f32 / 1024.0)
                } else {
                    format!("{}B", entry.size)
                };
                format!("  {:19} {:>5}", short, sz)
            };

            Text::new(
                &line,
                Point::new(4, y),
                MonoTextStyle::new(&FONT_6X10, txt_color),
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }

        if entries.len() > BROWSER_VISIBLE {
            let indicator = format!("{}/{}", sel + 1, entries.len());
            Text::with_text_style(
                &indicator,
                Point::new(238, 39),
                MonoTextStyle::new(&FONT_6X10, WHITE),
                TextStyleBuilder::new().alignment(Alignment::Right).build(),
            )
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }
    }

    Text::with_text_style(
        "UP/DWN:nav  MID:open  LFT:back",
        Point::new(120, 224),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    if let Some(ip) = web_ip {
        let ip_line = format!("WiFi: {}", ip);
        Text::with_text_style(
            &ip_line,
            Point::new(120, 236),
            MonoTextStyle::new(&FONT_6X10, GREEN),
            centered,
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    Ok(())
}

fn run_view_raw_file<D>(
    display: &mut D,
    name: &str,
    data: &[u8],
    btn_up: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_dwn: &PinDriver<'_, esp_idf_hal::gpio::Input>,
    btn_lft: &PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    const BYTES_PER_ROW: usize = 8;
    const ROWS_PER_PAGE: usize = 9;
    let total_rows = (data.len() + BYTES_PER_ROW - 1) / BYTES_PER_ROW;
    if total_rows == 0 {
        return Ok(());
    }
    let max_offset = if total_rows > ROWS_PER_PAGE {
        total_rows - ROWS_PER_PAGE
    } else {
        0
    };
    let mut row_offset: usize = 0;
    draw_raw_hex_view(display, name, data, row_offset)?;
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
            row_offset = row_offset.saturating_sub(ROWS_PER_PAGE);
            draw_raw_hex_view(display, name, data, row_offset)?;
        }
        if btn_dwn.is_low() {
            while btn_dwn.is_low() {
                FreeRtos::delay_ms(10);
            }
            if row_offset < max_offset {
                row_offset = (row_offset + ROWS_PER_PAGE).min(max_offset);
                draw_raw_hex_view(display, name, data, row_offset)?;
            }
        }
        FreeRtos::delay_ms(30);
    }
    Ok(())
}

fn draw_raw_hex_view<D>(
    display: &mut D,
    name: &str,
    data: &[u8],
    row_offset: usize,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    const BYTES_PER_ROW: usize = 8;
    const ROWS_PER_PAGE: usize = 9;
    display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;
    let centered = TextStyleBuilder::new().alignment(Alignment::Center).build();

    let hdr = if name.len() > 26 {
        name.chars()
            .rev()
            .take(26)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    } else {
        name.to_string()
    };
    Text::with_text_style(
        &hdr,
        Point::new(120, 12),
        MonoTextStyle::new(&FONT_6X10, ORANGE),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    for r in 0..ROWS_PER_PAGE {
        let row = row_offset + r;
        let byte_start = row * BYTES_PER_ROW;
        if byte_start >= data.len() {
            break;
        }
        let row_bytes = &data[byte_start..(byte_start + BYTES_PER_ROW).min(data.len())];
        let mut line = format!("{:04X}:", byte_start);
        for b in row_bytes {
            line.push_str(&format!(" {:02X}", b));
        }
        let y = 26 + (r as i32) * 21;
        Text::new(
            &line,
            Point::new(2, y),
            MonoTextStyle::new(&FONT_6X10, WHITE),
        )
        .draw(display)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    }

    let byte_pos = row_offset * BYTES_PER_ROW;
    let pct = if !data.is_empty() {
        (byte_pos * 100 / data.len()).min(100)
    } else {
        100
    };
    let footer = format!("{}% ({}/{})  LFT:back", pct, byte_pos, data.len());
    Text::with_text_style(
        &footer,
        Point::new(120, 231),
        MonoTextStyle::new(&FONT_6X10, GRAY),
        centered,
    )
    .draw(display)
    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Ok(())
}

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
                "RIGHT: dumps sauves",
                Point::new(120, 175),
                MonoTextStyle::new(&FONT_6X10, ORANGE),
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
