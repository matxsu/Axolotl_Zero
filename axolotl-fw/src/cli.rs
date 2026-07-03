//! Console série (CLI) sur l'USB série (UART0), en parallèle du menu joystick.
//!
//! Donne un moyen verbeux de voir ce qui se passe et de piloter la SD sans
//! écran : `status`, `ls`, `tree`, `cat`, `rm`, `mkdir`, `creds`. N'accède
//! **qu'à la SD (VFS, thread-safe) et aux infos système** — jamais au PN532 ni
//! au modem (ceux-ci appartiennent au thread menu → pas de contention).
//!
//! Sortie via `println!`/`print!` : c'est de l'I/O console (réponses au user),
//! pas du logging — l'interdiction `println!` du projet vise les logs, pas un
//! REPL. Se branche sur `cargo espflash monitor` (les touches tapées y sont
//! renvoyées vers l'UART RX de l'ESP32).

use esp_idf_svc::hal::delay::FreeRtos;
use std::io::Read;

/// Lance la console série dans un thread détaché.
pub fn spawn() {
    let _ = std::thread::Builder::new()
        .stack_size(8192)
        .name("cli".into())
        .spawn(cli_loop);
}

fn cli_loop() {
    println!("\n[axolotl-cli] prêt — tape 'help'.");
    let mut line = String::new();
    loop {
        let mut b = [0u8; 1];
        match std::io::stdin().read(&mut b) {
            Ok(1) => {
                let c = b[0];
                if c == b'\n' || c == b'\r' {
                    let cmd = line.trim().to_string();
                    if !cmd.is_empty() {
                        exec(&cmd);
                        print!("axolotl> ");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                    line.clear();
                } else if line.len() < 512 {
                    line.push(c as char);
                }
            }
            // Pas de donnée (lecture non bloquante) ou EOF : on cède la main.
            _ => FreeRtos::delay_ms(20),
        }
    }
}

fn exec(line: &str) {
    let cmd = line.split_whitespace().next().unwrap_or("");
    let arg = line[cmd.len()..].trim();
    match cmd {
        "help" | "?" => help(),
        "status" | "df" => status(),
        "ls" | "dir" => ls(if arg.is_empty() { "/sdcard" } else { arg }),
        "tree" => tree(if arg.is_empty() { "/sdcard" } else { arg }, 0),
        "cat" => cat(arg),
        "creds" => cat("/sdcard/loot/creds.csv"),
        "rm" => rm(arg),
        "mkdir" => mkdir(arg),
        _ => println!("commande inconnue: '{cmd}' (tape 'help')"),
    }
}

fn help() {
    println!("Commandes Axolotl CLI :");
    println!("  help | ?           cette aide");
    println!("  status | df        heap libre, uptime, SD, version");
    println!("  ls [chemin]        liste un dossier (défaut /sdcard)");
    println!("  tree [chemin]      arborescence récursive (profondeur 3)");
    println!("  cat <chemin>       affiche un fichier (texte)");
    println!("  creds              affiche /sdcard/loot/creds.csv");
    println!("  rm <chemin>        supprime un fichier");
    println!("  mkdir <chemin>     crée un dossier");
}

fn status() {
    let heap = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
    let min = unsafe { esp_idf_svc::sys::esp_get_minimum_free_heap_size() };
    let up = unsafe { esp_idf_svc::sys::esp_timer_get_time() } / 1_000_000;
    println!("heap libre : {heap} o  (min jamais atteint : {min} o)");
    println!("uptime     : {up} s");
    println!("SD montée  : {}", std::fs::metadata("/sdcard").is_ok());
    println!("spiflash   : {}", std::fs::metadata("/spiflash").is_ok());
    println!("version    : {}", env!("CARGO_PKG_VERSION"));
}

fn ls(path: &str) {
    match std::fs::read_dir(path) {
        Ok(rd) => {
            let mut n = 0u32;
            for e in rd.flatten() {
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                let name = e.file_name().to_string_lossy().into_owned();
                if is_dir {
                    println!("  <dir>     {name}");
                } else {
                    let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
                    println!("  {sz:>8}  {name}");
                }
                n += 1;
            }
            println!("({n} entrée(s) dans {path})");
        }
        Err(e) => println!("ls: {path}: {e}"),
    }
}

fn tree(path: &str, depth: usize) {
    if depth > 3 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(path) else {
        if depth == 0 {
            println!("tree: {path}: introuvable");
        }
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let indent = "  ".repeat(depth);
        if is_dir {
            println!("{indent}{name}/");
            tree(&format!("{path}/{name}"), depth + 1);
        } else {
            let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
            println!("{indent}{name} ({sz} o)");
        }
    }
}

fn cat(path: &str) {
    if path.is_empty() {
        println!("usage: cat <chemin>");
        return;
    }
    match std::fs::read(path) {
        Ok(data) => {
            println!("--- {path} ({} o) ---", data.len());
            print!("{}", String::from_utf8_lossy(&data));
            println!("\n--- fin ---");
        }
        Err(e) => println!("cat: {path}: {e}"),
    }
}

fn rm(path: &str) {
    if path.is_empty() {
        println!("usage: rm <chemin>");
        return;
    }
    match std::fs::remove_file(path) {
        Ok(_) => println!("supprimé: {path}"),
        Err(e) => println!("rm: {path}: {e}"),
    }
}

fn mkdir(path: &str) {
    if path.is_empty() {
        println!("usage: mkdir <chemin>");
        return;
    }
    match std::fs::create_dir_all(path) {
        Ok(_) => println!("créé: {path}"),
        Err(e) => println!("mkdir: {path}: {e}"),
    }
}
