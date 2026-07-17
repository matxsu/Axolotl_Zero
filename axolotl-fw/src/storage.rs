//! Drivers stockage — SD card FAT via esp-idf-svc + FAT interne sur flash.
//! SPI2 partagé avec le display (MOSI=11, SCK=12, MISO=13, CS=6).

use std::borrow::Borrow;
use std::fs;
use std::io::Write;

use esp_idf_hal::{
    delay::FreeRtos,
    gpio::{AnyInputPin, AnyOutputPin},
    sd::{spi::SdSpiHostDriver, SdCardConfiguration, SdCardDriver},
    spi::SpiDriver,
};
use esp_idf_svc::fs::fatfs::Fatfs;

const MOUNT_POINT: &str = "/sdcard";
const FLASH_MOUNT: &str = "/spiflash";

/// Écriture d'un fichier sur le stockage actif (SD ou flash) sans exposer le
/// type générique. Les lectures/listings passent par `std::fs` (2 racines).
pub trait SdWrite {
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()>;
}

pub struct SdStorage<'d, T = SpiDriver<'d>>
where
    T: Borrow<SpiDriver<'d>> + 'd,
{
    // Doit rester monté : `MountedFatfs` enregistre la FAT dans le VFS, sans quoi
    // `/sdcard` n'existe pas côté `std::fs` et toute écriture échoue en ENOENT.
    _mounted: MountedFatfs<Fatfs<SdCardDriver<SdSpiHostDriver<'d, T>>>>,
}

impl<'d, T> SdStorage<'d, T>
where
    T: Borrow<SpiDriver<'d>> + 'd,
{
    /// Initialise le driver SD et monte le filesystem FAT.
    /// `spi` peut être un `SpiDriver` owned ou une `&SpiDriver` partagée.
    pub fn new(spi: T, cs: AnyOutputPin<'d>) -> anyhow::Result<Self> {
        let spi_host = SdSpiHostDriver::new(
            spi,
            Some(cs),
            None::<AnyInputPin>,
            None::<AnyInputPin>,
            None::<AnyInputPin>,
            None, // wp_active_high — ESP-IDF v5.2+
        )?;

        // Délai après les 74 clocks d'init sdspi : certaines cartes ont besoin de
        // 800-1000ms après la première communication SPI avant d'accepter CMD0+CMD41.
        FreeRtos::delay_ms(2000);

        // 400 kHz pour l'init (spec SD) puis 1 MHz transfert — breadboard avec fils longs
        let mut sd_config = SdCardConfiguration::new();
        sd_config.speed_khz = 400;
        let sd_card = SdCardDriver::new_spi(spi_host, &sd_config)?;
        log::info!("SD: carte detectee");

        let fatfs = Fatfs::new_sdcard(0, sd_card)?;
        // Enregistre le FS dans le VFS à /sdcard (comme InternalFs pour /spiflash) :
        // c'est CE montage qui crée le chemin `/sdcard` pour std::fs.
        let mounted = MountedFatfs::mount(fatfs, MOUNT_POINT, 4)
            .map_err(|e| anyhow::anyhow!("SD VFS mount {}: {:?}", MOUNT_POINT, e))?;
        log::info!("SD: FAT monte sur {}", MOUNT_POINT);

        let _ = fs::create_dir_all("/sdcard/NFC/dumps");

        Ok(Self { _mounted: mounted })
    }

    /// Écrit `data` dans `/sdcard{path}` (crée ou écrase).
    pub fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let full = format!("{}{}", MOUNT_POINT, path);
        // Recrée l'arborescence avant l'écriture, sinon File::create renvoie un
        // ENOENT trompeur. On logge l'échec au lieu de le swallow (vraie cause).
        if let Some(parent) = std::path::Path::new(&full).parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                log::warn!("SD create_dir_all {}: {}", parent.display(), e);
            }
        }
        let mut f =
            fs::File::create(&full).map_err(|e| anyhow::anyhow!("SD create {}: {}", full, e))?;
        f.write_all(data)
            .map_err(|e| anyhow::anyhow!("SD write {}: {}", full, e))?;
        log::info!("SD: {} ({} bytes)", full, data.len());
        Ok(())
    }
}

impl<'d, T> SdWrite for SdStorage<'d, T>
where
    T: Borrow<SpiDriver<'d>> + 'd,
{
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        SdStorage::write_file(self, path, data)
    }
}

// ── Internal flash FAT (wear-levelling) ────────────────────────────────────

use esp_idf_svc::{
    handle::RawHandle,
    io::vfs::MountedFatfs,
    partition::{EspPartition, EspWlPartition},
};

pub struct InternalFs {
    // Drop order: mounted first (unregisters VFS), then wl (unmounts WL).
    _mounted: MountedFatfs<Fatfs<()>>,
    _wl: EspWlPartition<EspPartition>,
}

impl InternalFs {
    /// Monte la partition FAT "storage" sur flash interne via VFS à /spiflash.
    /// Crée /spiflash/NFC/dumps/ si absent.
    pub fn new() -> anyhow::Result<Self> {
        let partition = unsafe { EspPartition::cnew(c"storage") }
            .map_err(|e| anyhow::anyhow!("Partition lookup: {e:?}"))?
            .ok_or_else(|| anyhow::anyhow!("Partition 'storage' introuvable"))?;

        let wl = EspWlPartition::new(partition).map_err(|e| anyhow::anyhow!("WL mount: {e:?}"))?;

        let wl_handle = wl.handle();
        let fatfs = unsafe { Fatfs::new_wl_part(0, wl_handle) }
            .map_err(|e| anyhow::anyhow!("Fatfs diskio: {e:?}"))?;

        let mounted = MountedFatfs::mount(fatfs, FLASH_MOUNT, 8)
            .map_err(|e| anyhow::anyhow!("VFS mount: {e:?}"))?;

        log::info!("InternalFs: FAT monte sur {}", FLASH_MOUNT);
        let _ = fs::create_dir_all(format!("{}/NFC/dumps", FLASH_MOUNT));

        Ok(Self {
            _mounted: mounted,
            _wl: wl,
        })
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let full = format!("{}{}", FLASH_MOUNT, path);
        if let Some(parent) = std::path::Path::new(&full).parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                log::warn!("Flash create_dir_all {}: {}", parent.display(), e);
            }
        }
        let mut f =
            fs::File::create(&full).map_err(|e| anyhow::anyhow!("Flash create {}: {}", full, e))?;
        f.write_all(data)
            .map_err(|e| anyhow::anyhow!("Flash write {}: {}", full, e))?;
        log::info!("Flash: {} ({} bytes)", full, data.len());
        Ok(())
    }
}

impl SdWrite for InternalFs {
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        InternalFs::write_file(self, path, data)
    }
}
