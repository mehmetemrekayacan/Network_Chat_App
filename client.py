"""
TCP tabanlı chat istemcisi.
- Çok kullanıcılı, güvenilirlik mekanizmalı TCP chat istemcisi.
- Protokol: network/protocol.py (v1.2)
- Özellikler: bağlantı yönetimi, mesaj iletimi, versiyon kontrolü, hata yönetimi.
"""
import socket
import threading
import time
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION, MIN_SUPPORTED_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, ERROR_CODES, version_compatible
)

def receive_messages(sock):
    """Mesaj alma ve işleme thread'i"""
    while True:
        try:
            data = sock.recv(MAX_PACKET_SIZE)
            if not data:
                print("[!] Sunucu bağlantısı kesildi")
                break
                
            packet = parse_packet(data)
            if not packet:
                print("[!] Geçersiz paket alındı")
                continue
                
            header = packet["header"]
            msg_type = header["type"]
            
            # Hata kodu kontrolü
            if "error_code" in header:
                error_code = header["error_code"]
                if error_code != 0x00:  # Başarılı değilse
                    print(f"[!] Sunucu hatası: {ERROR_CODES.get(error_code, 'Bilinmeyen hata')}")
                    if error_code == 0x02:  # Versiyon uyumsuzluğu
                        print(f"[!] Sunucu protokol versiyonu: {header.get('version', 'Bilinmiyor')}")
                        print(f"[!] İstemci protokol versiyonu: {PROTOCOL_VERSION}")
                        break
                    continue
            
            # Versiyon kontrolü yanıtı
            if msg_type == "version_check":
                if "extra" in packet["payload"]:
                    extra = packet["payload"]["extra"]
                    server_version = extra.get("server_version", "Bilinmiyor")
                    min_version = extra.get("min_version", "Bilinmiyor")
                    print(f"[*] Sunucu protokol versiyonu: {server_version}")
                    print(f"[*] Minimum desteklenen versiyon: {min_version}")
                continue
            
            # Normal mesaj işleme
            sender = header["sender"]
            text = packet["payload"]["text"]
            
            # Mesaj tipine göre özel format
            if msg_type == "error":
                print(f"\n[!] Hata: {text}")
            elif msg_type == "join":
                print(f"\n[+] {text}")
            elif msg_type == "leave":
                print(f"\n[-] {text}")
            elif msg_type == "userlist":
                if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
                    users = packet["payload"]["extra"]["users"]
                    print("\n--- Bağlı Kullanıcılar ---")
                    for user in users:
                        version = user.get("version", "Bilinmiyor")
                        print(f"{user['username']} (v{version})")
                    print("-------------------------")
            else:
                print(f"\n>> {sender}: {text}")
                
        except Exception as e:
            print(f"[!] Mesaj alımında hata: {e}")
            break

def send_messages(sock, username):
    """Mesaj gönderme"""
    # Versiyon kontrolü yap
    version_check = build_packet(username, "version_check")
    sock.send(version_check)
    
    # JOIN mesajı gönder
    join_packet = build_packet(username, "join", "katıldı")
    sock.send(join_packet)
    print(f"[*] Protokol v{PROTOCOL_VERSION} ile sunucuya bağlanıldı")
    
    while True:
        try:
            message = input("Sen: ").strip()
            
            # Özel komutlar
            if message.lower() == "version":
                # Versiyon kontrolü
                version_check = build_packet(username, "version_check")
                sock.send(version_check)
                continue
            elif message.lower() == "quit":
                # Çıkış mesajı gönder
                leave_packet = build_packet(username, "leave", "ayrıldı")
                sock.send(leave_packet)
                break
                
            if not message:
                continue
                
            # Mesajı gönder
            packet = build_packet(username, "message", message)
            sock.send(packet)
            
        except KeyboardInterrupt:
            # Çıkış mesajı gönder
            try:
                leave_packet = build_packet(username, "leave", "ayrıldı")
                sock.send(leave_packet)
            except:
                pass
            break
        except Exception as e:
            print(f"[!] Mesaj gönderme hatası: {e}")

def start_client():
    """TCP istemciyi başlat"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        sock.connect(("localhost", 12345))
        print("[*] Sunucuya bağlanıldı")
        
        username = input("Kullanıcı adınız: ").strip()
        if not username:
            print("[!] Geçersiz kullanıcı adı")
            return
            
        print("\nÖzel komutlar:")
        print("- version: Protokol versiyonunu kontrol et")
        print("- quit: Sohbetten ayrıl\n")
        
        # Alıcı thread'i başlat
        receiver = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
        receiver.start()
        
        # Mesaj gönderme döngüsü
        send_messages(sock, username)
        
    except ConnectionRefusedError:
        print("[!] Sunucuya bağlanılamadı")
    except Exception as e:
        print(f"[!] Bağlantı hatası: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    start_client()
