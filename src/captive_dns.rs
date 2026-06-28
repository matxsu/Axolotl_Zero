use std::net::UdpSocket;
use log::info;

// Mini serveur DNS : repond a TOUTE requete par l IP du portail (192.168.71.1).
// C est le coeur du portail captif facon aeroport : le telephone croit que
// tous les domaines pointent vers nous, donc son test de connectivite tombe
// sur notre page et l ouvre automatiquement.
pub fn run(ip: [u8; 4]) {
    let socket = match UdpSocket::bind("0.0.0.0:53") {
        Ok(s) => s,
        Err(e) => {
            info!("DNS: bind port 53 impossible: {:?}", e);
            return;
        }
    };
    info!("DNS captif demarre sur le port 53");

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
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
        resp.extend_from_slice(&buf[4..6]);    // QDCOUNT (nb de questions) recopie
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1 reponse
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Recopie la question (du byte 12 jusqu a la fin du paquet recu)
        resp.extend_from_slice(&buf[12..len]);

        // Reponse (answer) : pointeur vers le nom (0xC00C), type A, classe IN
        resp.extend_from_slice(&[0xC0, 0x0C]);       // pointeur vers la question
        resp.extend_from_slice(&[0x00, 0x01]);       // TYPE A
        resp.extend_from_slice(&[0x00, 0x01]);       // CLASS IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s
        resp.extend_from_slice(&[0x00, 0x04]);       // longueur data = 4 octets
        resp.extend_from_slice(&ip);                 // notre IP

        let _ = socket.send_to(&resp, src);
    }
}