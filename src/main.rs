#![allow(dead_code)]

mod wifi_scan;
mod wifi_ap;
mod display;
mod logo;
mod badusb;
mod captive_dns;
mod wifi_sniff;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::nvs::EspDefaultNvsPartition;

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    std::thread::Builder::new()
        .stack_size(65536)
        .spawn(move || display::run(sys_loop, nvs))?
        .join()
        .map_err(|_| anyhow::anyhow!("thread display panic"))?
}
