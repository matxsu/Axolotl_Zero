//! Driver SD card — FAT filesystem via esp-idf-svc
//! CS=GPIO6, SPI2 partagé (MOSI=11, SCK=12, MISO=13)

use esp_idf_hal::{
    gpio::AnyOutputPin,
    sd::{spi::SdSpiHostDriver, SdCardConfiguration, SdCardDriver},
    spi::SpiDriver,
};
use esp_idf_svc::fs::fatfs::Fatfs;
use std::fs;
use std::io::Write;

const MOUNT_POINT: &str = "/sdcard";

pub struct SdStorage<'d> {
    _fatfs: Fatfs<SdCardDriver<SdSpiHostDriver<'d, SpiDriver<'d>>>>,
}

impl<'d> SdStorage<'d> {
    /// Initialise le driver SD et monte le filesystem FAT
    pub fn new(spi: SpiDriver<'d>, cs: AnyOutputPin) -> anyhow::Result<Self> {
        let spi_host = SdSpiHostDriver::new(
            spi,
            Some(cs),
            None::<AnyOutputPin>, // CD
            None::<AnyOutputPin>, // WP
            None::<AnyOutputPin>, // INT
            None,                 // wp_active_high
        )?;

        let sd_card = SdCardDriver::new_spi(spi_host, &SdCardConfiguration::new())?;
        log::info!("SD: carte détectée");

        let fatfs = Fatfs::new_sdcard(0, sd_card)?;
        log::info!("SD: FAT monté sur {}", MOUNT_POINT);

        // Créer les dossiers NFC si absents
        let _ = fs::create_dir_all("/sdcard/NFC/dumps");
        let _ = fs::create_dir_all("/sdcard/NFC");

        Ok(Self { _fatfs: fatfs })
    }

    /// Écrit du texte dans un fichier (crée ou écrase)
    pub fn write_file(&self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let full = format!("/sdcard{}", path);
        let mut f =
            fs::File::create(&full).map_err(|e| anyhow::anyhow!("SD write {}: {}", full, e))?;
        f.write_all(data)
            .map_err(|e| anyhow::anyhow!("SD write data: {}", e))?;
        log::info!("SD: écrit {} ({} bytes)", full, data.len());
        Ok(())
    }

    /// Lit un fichier complet
    pub fn read_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let full = format!("/sdcard{}", path);
        fs::read(&full).map_err(|e| anyhow::anyhow!("SD read {}: {}", full, e))
    }

    /// Vérifie si un fichier existe
    pub fn exists(&self, path: &str) -> bool {
        fs::metadata(format!("/sdcard{}", path)).is_ok()
    }

    /// Liste les fichiers d'un dossier
    pub fn list_dir(&self, path: &str) -> anyhow::Result<Vec<String>> {
        let full = format!("/sdcard{}", path);
        let entries =
            fs::read_dir(&full).map_err(|e| anyhow::anyhow!("SD list {}: {}", full, e))?;
        let mut names = Vec::new();
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }
}
