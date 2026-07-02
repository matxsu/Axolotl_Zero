//! Mini serveur DNS pour portail captif.
//!
//! Porté depuis `feature/wifi_attacks:src/captive_dns.rs`. Adaptation menu :
//! la boucle est rendue **arrêtable** via [`STOP`] + un timeout de lecture, pour
//! que [`super::eviltwin`] puisse libérer le port 53 en sortie et être ré-entré
//! (sinon un 2ᵉ lancement échouerait au `bind`).
//!
//! Répond à TOUTE requête par l'IP du portail : le téléphone croit que tous les
//! domaines pointent vers nous, son test de connectivité tombe sur notre page
//! et l'ouvre automatiquement (portail captif façon aéroport).

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use log::info;

/// Drapeau d'arrêt du thread DNS. Mis à `true` par l'appelant pour sortir de
/// [`run`] proprement ; remis à `false` au démarrage de chaque `run`.
pub static STOP: AtomicBool = AtomicBool::new(false);

/// Écoute sur le port 53 et renvoie `ip` pour chaque requête. À lancer dans un
/// thread ; sort quand [`STOP`] passe à `true`.
pub fn run(ip: [u8; 4]) {
    STOP.store(false, Ordering::Relaxed);
    let socket = match UdpSocket::bind("0.0.0.0:53") {
        Ok(s) => s,
        Err(e) => {
            info!("DNS: bind port 53 impossible: {:?}", e);
            return;
        }
    };
    // Timeout de lecture pour rester réactif au drapeau STOP.
    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
    info!("DNS captif demarre sur le port 53");

    let mut buf = [0u8; 512];
    loop {
        if STOP.load(Ordering::Relaxed) {
            info!("DNS captif arrete");
            return;
        }
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue, // timeout inclus → on reboucle et on teste STOP
        };
        if len < 12 {
            continue;
        }

        // Construit une reponse DNS minimale qui pointe vers notre IP.
        let mut resp: Vec<u8> = Vec::with_capacity(len + 16);
        // En-tete : on reprend l ID de la requete
        resp.push(buf[0]);
        resp.push(buf[1]);
        resp.extend_from_slice(&[0x81, 0x80]); // flags: reponse standard, pas d erreur
        resp.extend_from_slice(&buf[4..6]); // QDCOUNT (nb de questions) recopie
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1 reponse
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Recopie la question (du byte 12 jusqu a la fin du paquet recu)
        resp.extend_from_slice(&buf[12..len]);

        // Reponse (answer) : pointeur vers le nom (0xC00C), type A, classe IN
        resp.extend_from_slice(&[0xC0, 0x0C]); // pointeur vers la question
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s
        resp.extend_from_slice(&[0x00, 0x04]); // longueur data = 4 octets
        resp.extend_from_slice(&ip); // notre IP

        let _ = socket.send_to(&resp, src);
    }
}
