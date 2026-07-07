//! WiFi AP + serveur HTTP pour le file browser SD.
//!
//! Réseau : SSID=AxolotlZero  pass=axolotl1  IP=192.168.71.1

pub mod captive_dns;
pub mod eviltwin;
pub mod scan;
pub mod sniff;

use embedded_svc::http::Method;
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    http::server::{Configuration as HttpCfg, EspHttpServer},
    nvs::EspDefaultNvsPartition,
    wifi::{AccessPointConfiguration, AuthMethod, BlockingWifi, Configuration, EspWifi},
};

pub const AP_SSID: &str = "AxolotlZero";
pub const AP_PASS: &str = "axolotl1";
pub const AP_IP: &str = "192.168.71.1";

static INDEX_HTML: &[u8] = include_bytes!("index.html");

pub struct WebServer<'d> {
    _wifi: BlockingWifi<EspWifi<'d>>,
    _http: EspHttpServer<'d>,
}

impl<'d> WebServer<'d> {
    pub fn start(
        modem: impl esp_idf_svc::hal::modem::WifiModemPeripheral + 'd,
        sysloop: EspSystemEventLoop,
        nvs: EspDefaultNvsPartition,
    ) -> anyhow::Result<Self> {
        let mut wifi =
            BlockingWifi::wrap(EspWifi::new(modem, sysloop.clone(), Some(nvs))?, sysloop)?;

        wifi.set_configuration(&Configuration::AccessPoint(AccessPointConfiguration {
            ssid: AP_SSID
                .try_into()
                .map_err(|_| anyhow::anyhow!("SSID trop long"))?,
            password: AP_PASS
                .try_into()
                .map_err(|_| anyhow::anyhow!("pass trop long"))?,
            auth_method: AuthMethod::WPA2Personal,
            max_connections: 4,
            ..Default::default()
        }))?;

        wifi.start()?;
        log::info!(
            "WiFi AP actif — SSID={} pass={} IP={}",
            AP_SSID,
            AP_PASS,
            AP_IP
        );

        let mut http = EspHttpServer::new(&HttpCfg {
            stack_size: 10240,
            ..Default::default()
        })?;

        // GET / → page HTML embarquée (file browser)
        http.fn_handler("/", Method::Get, |req| {
            req.into_response(
                200,
                Some("OK"),
                &[("Content-Type", "text/html; charset=utf-8")],
            )?
            .write(INDEX_HTML)
            .map_err(crate::anyhow_dbg)?;
            Ok::<(), anyhow::Error>(())
        })?;

        // GET /api/status
        http.fn_handler("/api/status", Method::Get, |req| {
            let sd_ok = std::fs::metadata("/sdcard").is_ok();
            let spiflash_ok = std::fs::metadata("/spiflash").is_ok();
            let body = format!(r#"{{"sd":{},"spiflash":{}}}"#, sd_ok, spiflash_ok);
            req.into_response(200, Some("OK"), &[("Content-Type", "application/json")])?
                .write(body.as_bytes())
                .map_err(crate::anyhow_dbg)?;
            Ok::<(), anyhow::Error>(())
        })?;

        // GET /api/files?path=<dossier> → liste n'importe quel dossier
        http.fn_handler("/api/files", Method::Get, |req| {
            let mut dir = url_param(req.uri(), "path");
            if dir.is_empty() {
                dir = "/sdcard".to_string();
            }
            let json = list_dir_json(&dir);
            req.into_response(200, Some("OK"), &[("Content-Type", "application/json")])?
                .write(json.as_bytes())
                .map_err(crate::anyhow_dbg)?;
            Ok::<(), anyhow::Error>(())
        })?;

        // GET /api/rm?path=...
        http.fn_handler("/api/rm", Method::Get, |req| {
            let path = url_param(req.uri(), "path");
            let ok = !path.is_empty() && std::fs::remove_file(&path).is_ok();
            let body: &[u8] = if ok {
                b"{\"ok\":true}"
            } else {
                b"{\"ok\":false}"
            };
            req.into_response(200, Some("OK"), &[("Content-Type", "application/json")])?
                .write(body)
                .map_err(crate::anyhow_dbg)?;
            Ok::<(), anyhow::Error>(())
        })?;

        // GET /file?path=... → télécharger un fichier
        http.fn_handler("/file", Method::Get, |req| {
            let path = url_param(req.uri(), "path");
            match std::fs::read(&path) {
                Ok(data) => {
                    // Nom de fichier explicite => le navigateur télécharge avec la
                    // vraie extension (.pcap/.mfd/.csv…) au lieu de « file »/HTML.
                    let name = std::path::Path::new(&path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("download");
                    let cd = format!("attachment; filename=\"{}\"", name);
                    let mut resp = req.into_response(
                        200,
                        Some("OK"),
                        &[
                            ("Content-Disposition", cd.as_str()),
                            ("Content-Type", "application/octet-stream"),
                        ],
                    )?;
                    write_all(&mut resp, &data).map_err(crate::anyhow_dbg)?;
                }
                Err(_) => {
                    req.into_response(404, Some("Not Found"), &[])?
                        .write(b"not found")
                        .map_err(crate::anyhow_dbg)?;
                }
            }
            Ok::<(), anyhow::Error>(())
        })?;

        // POST /file?path=... → uploader un fichier
        http.fn_handler("/file", Method::Post, |mut req| {
            let path = url_param(req.uri(), "path");
            if path.is_empty() {
                req.into_response(400, Some("Bad Request"), &[])?
                    .write(b"missing path")
                    .map_err(crate::anyhow_dbg)?;
                return Ok(());
            }
            let mut body: Vec<u8> = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                match req.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&buf[..n]),
                }
            }
            if let Some(p) = std::path::Path::new(&path).parent() {
                let _ = std::fs::create_dir_all(p);
            }
            match std::fs::write(&path, &body) {
                Ok(_) => {
                    req.into_response(200, Some("OK"), &[])?
                        .write(b"ok")
                        .map_err(crate::anyhow_dbg)?;
                }
                Err(e) => {
                    let msg = format!("error: {e}");
                    req.into_response(500, Some("Error"), &[])?
                        .write(msg.as_bytes())
                        .map_err(crate::anyhow_dbg)?;
                }
            }
            Ok::<(), anyhow::Error>(())
        })?;

        Ok(Self {
            _wifi: wifi,
            _http: http,
        })
    }
}

fn list_dir_json(path: &str) -> String {
    let Ok(rd) = std::fs::read_dir(path) else {
        return "[]".to_string();
    };
    let mut items: Vec<(String, String)> = rd
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().replace('"', "\\\"");
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            let key = format!("{}{}", if is_dir { '0' } else { '1' }, name);
            (
                key,
                format!("{{\"n\":\"{name}\",\"s\":{size},\"d\":{is_dir}}}"),
            )
        })
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let json: Vec<String> = items.into_iter().map(|(_, v)| v).collect();
    format!("[{}]", json.join(","))
}

fn url_param(uri: &str, key: &str) -> String {
    let needle = format!("?{key}=");
    let alt = format!("&{key}=");
    let raw_start = uri
        .find(needle.as_str())
        .map(|p| p + needle.len())
        .or_else(|| uri.find(alt.as_str()).map(|p| p + alt.len()));
    let Some(start) = raw_start else {
        return String::new();
    };
    let raw = match uri[start..].find('&') {
        Some(end) => &uri[start..start + end],
        None => &uri[start..],
    };
    pct_decode(raw)
}

fn pct_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push((h << 4 | l) as char);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { ' ' } else { b[i] as char });
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn write_all<W: embedded_svc::io::Write>(w: &mut W, data: &[u8]) -> Result<(), W::Error> {
    let mut off = 0;
    while off < data.len() {
        let n = w.write(&data[off..])?;
        if n == 0 {
            break;
        }
        off += n;
    }
    Ok(())
}
