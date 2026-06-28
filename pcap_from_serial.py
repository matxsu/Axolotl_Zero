import sys, struct, re

def main(src, dst):
    frames = []
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.search(r"PCAP:([0-9A-Fa-f]+)", line)
            if m:
                h = m.group(1)
                if len(h) % 2 == 0:
                    frames.append(bytes.fromhex(h))
    with open(dst, "wb") as out:
        # En-tete global pcap : magic, v2.4, zones reservees, snaplen, DLT=105 (802.11)
        out.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
        for i, fr in enumerate(frames):
            # En-tete par paquet : ts_sec, ts_usec, caplen, origlen
            out.write(struct.pack("<IIII", i, 0, len(fr), len(fr)))
            out.write(fr)
    print(f"{len(frames)} trames EAPOL ecrites dans {dst}")

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "capture.txt"
    dst = sys.argv[2] if len(sys.argv) > 2 else "handshake.pcap"
    main(src, dst)
