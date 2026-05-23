//! Driver SD card — FAT filesystem via esp-idf-svc
//! Partage SPI2 avec le display (MOSI=11, SCK=12, MISO=13, CS=6)

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

/// Trait minimal utilisé par les fonctions UI pour écrire / lister.
/// Permet de passer `&dyn SdWrite` sans exposer le type générique complet.
pub trait SdWrite {
    fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()>;
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
        FreeRtos::delay_ms(1000);

        // 2 MHz max sur breadboard (fils longs = bruit → corruption de blocs à 20 MHz par défaut)
        let mut sd_config = SdCardConfiguration::new();
        sd_config.speed_khz = 2000;
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

    fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        SdStorage::list_dir(self, path)
    }
}
