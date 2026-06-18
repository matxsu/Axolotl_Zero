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

/// Trait minimal utilisé par les fonctions UI pour écrire / lister.
/// Permet de passer `&dyn SdWrite` sans exposer le type générique complet.
pub trait SdWrite {
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()>;
    fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>>;
    fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>>;
}

pub struct SdStorage<'d, T = SpiDriver<'d>>
where
    T: Borrow<SpiDriver<'d>> + 'd,
{
    _fatfs: Fatfs<SdCardDriver<SdSpiHostDriver<'d, T>>>,
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
        log::info!("SD: FAT monte sur {}", MOUNT_POINT);

        let _ = fs::create_dir_all("/sdcard/NFC/dumps");

        Ok(Self { _fatfs: fatfs })
    }

    /// Écrit `data` dans `/sdcard{path}` (crée ou écrase).
    pub fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let full = format!("{}{}", MOUNT_POINT, path);
        let mut f = fs::File::create(&full)
            .map_err(|e| anyhow::anyhow!("SD create {}: {}", full, e))?;
        f.write_all(data)
            .map_err(|e| anyhow::anyhow!("SD write {}: {}", full, e))?;
        log::info!("SD: {} ({} bytes)", full, data.len());
        Ok(())
    }

    /// Lit un fichier complet.
    pub fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let full = format!("{}{}", MOUNT_POINT, path);
        fs::read(&full).map_err(|e| anyhow::anyhow!("SD read {}: {}", full, e))
    }

    /// Liste les noms de fichiers d'un dossier.
    pub fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        let full = format!("{}{}", MOUNT_POINT, path);
        let entries = fs::read_dir(&full)
            .map_err(|e| anyhow::anyhow!("SD list {}: {}", full, e))?;
        let mut names = Vec::new();
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    /// Vérifie si un fichier existe.
    #[allow(dead_code)]
    pub fn exists(&self, path: &str) -> bool {
        fs::metadata(format!("{}{}", MOUNT_POINT, path)).is_ok()
    }
}

impl<'d, T> SdWrite for SdStorage<'d, T>
where
    T: Borrow<SpiDriver<'d>> + 'd,
{
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        SdStorage::write_file(self, path, data)
    }

    fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        SdStorage::read_file(self, path)
    }

    fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        SdStorage::list_dir(self, path)
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

        let wl = EspWlPartition::new(partition)
            .map_err(|e| anyhow::anyhow!("WL mount: {e:?}"))?;

        let wl_handle = wl.handle();
        let fatfs = unsafe { Fatfs::new_wl_part(0, wl_handle) }
            .map_err(|e| anyhow::anyhow!("Fatfs diskio: {e:?}"))?;

        let mounted = MountedFatfs::mount(fatfs, FLASH_MOUNT, 8)
            .map_err(|e| anyhow::anyhow!("VFS mount: {e:?}"))?;

        log::info!("InternalFs: FAT monte sur {}", FLASH_MOUNT);
        let _ = fs::create_dir_all(format!("{}/NFC/dumps", FLASH_MOUNT));

        Ok(Self { _mounted: mounted, _wl: wl })
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let full = format!("{}{}", FLASH_MOUNT, path);
        let mut f = fs::File::create(&full)
            .map_err(|e| anyhow::anyhow!("Flash create {}: {}", full, e))?;
        f.write_all(data)
            .map_err(|e| anyhow::anyhow!("Flash write {}: {}", full, e))?;
        log::info!("Flash: {} ({} bytes)", full, data.len());
        Ok(())
    }

    pub fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let full = format!("{}{}", FLASH_MOUNT, path);
        fs::read(&full).map_err(|e| anyhow::anyhow!("Flash read {}: {}", full, e))
    }

    pub fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        let full = format!("{}{}", FLASH_MOUNT, path);
        let entries = fs::read_dir(&full)
            .map_err(|e| anyhow::anyhow!("Flash list {}: {}", full, e))?;
        let mut names = Vec::new();
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    #[allow(dead_code)]
    pub fn exists(&self, path: &str) -> bool {
        fs::metadata(format!("{}{}", FLASH_MOUNT, path)).is_ok()
    }
}

impl SdWrite for InternalFs {
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        InternalFs::write_file(self, path, data)
    }

    fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        InternalFs::read_file(self, path)
    }

    fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        InternalFs::list_dir(self, path)
    }
}
