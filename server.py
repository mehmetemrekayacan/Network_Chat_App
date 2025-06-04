"""
TCP tabanlı chat sunucusu.
- Çok kullanıcılı, güvenilirlik mekanizmalı TCP chat sunucusu.
- Protokol: network/protocol.py (v1.2)
- Özellikler: kullanıcı listesi, bağlantı yönetimi, mesaj iletimi, hata yönetimi.
"""
import socket
import threading
import json
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION, MIN_SUPPORTED_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, ERROR_CODES, version_compatible
)

MAX_CLIENTS = 10  # Maksimum kullanıcı sayısı
clients = {}  # {client_socket: (username, ip, version)}
lock = threading.Lock()
server_socket = None
is_running = False

def handle_client(client_socket, client_address):
    """İstemci bağlantısını yönet"""
    print(f"[+] Yeni bağlantı: {client_address}")
    try:
        # İlk mesaj kullanıcı adı ve JOIN olmalı
        join_data = client_socket.recv(MAX_PACKET_SIZE)
        if not join_data:
            client_socket.close()
            return
            
        join_packet = parse_packet(join_data)
        if not join_packet:
            # Geçersiz paket
            try:
                client_socket.send(build_packet(
                    "SERVER", "error",
                    "Geçersiz paket formatı",
                    error_code=MESSAGE_TYPES["error"]
                ))
            except:
                pass
            client_socket.close()
            return
            
        # Versiyon kontrolü
        client_version = join_packet["header"]["version"]
        if not version_compatible(client_version):
            try:
                client_socket.send(build_packet(
                    "SERVER", "error",
                    f"Protokol versiyonu uyumsuz. Sunucu: {PROTOCOL_VERSION}, İstemci: {client_version}",
                    error_code=0x02
                ))
            except:
                pass
            client_socket.close()
            return
            
        # JOIN mesajı kontrolü
        if join_packet["header"]["type"] != "join":
            try:
                client_socket.send(build_packet(
                    "SERVER", "error",
                    "İlk mesaj JOIN olmalı",
                    error_code=0x05
                ))
            except:
                pass
            client_socket.close()
            return
            
        username = join_packet["header"]["sender"]
        
        with lock:
            if len(clients) >= MAX_CLIENTS:
                try:
                    client_socket.send(build_packet(
                        "SERVER", "error",
                        "Sunucu dolu, daha fazla kullanıcı kabul edilmiyor.",
                        error_code=0x06
                    ))
                except:
                    pass
                client_socket.close()
                print(f"[-] {client_address} reddedildi: Sunucu dolu.")
                return
                
            # Kullanıcı adı kontrolü
            if any(c[0] == username for c in clients.values()):
                try:
                    client_socket.send(build_packet(
                        "SERVER", "error",
                        "Bu kullanıcı adı zaten kullanımda.",
                        error_code=0x0A
                    ))
                except:
                    pass
                client_socket.close()
                return
                
            clients[client_socket] = (username, client_address[0], client_version)
            
        # Versiyon bilgisi ile kullanıcı listesi gönder
        broadcast_user_list()
        # Katılma mesajını yayınla
        broadcast(build_packet(
            "SERVER", "join",
            f"{username} sohbete katıldı (Protokol v{client_version})"
        ), exclude=[client_socket])
                
        while is_running:
            try:
                data = client_socket.recv(MAX_PACKET_SIZE)
                if not data:
                    break
                    
                packet = parse_packet(data)
                if not packet:
                    continue
                    
                # Hata kodu kontrolü
                if "error_code" in packet["header"]:
                    error_code = packet["header"]["error_code"]
                    if error_code != 0x00:  # Başarılı değilse
                        print(f"[!] İstemci hatası ({username}): {ERROR_CODES.get(error_code, 'Bilinmeyen hata')}")
                        continue
                    
                msg_type = packet["header"]["type"]
                sender = packet["header"]["sender"]
                text = packet["payload"]["text"]
                
                if msg_type == "message":
                    display_msg = build_packet("message", sender, text)
                    broadcast(display_msg)
                elif msg_type == "leave":
                    break
                elif msg_type == "version_check":
                    # Versiyon kontrolü yanıtı
                    client_socket.send(build_packet(
                        "SERVER", "version_check",
                        f"Sunucu protokol versiyonu: {PROTOCOL_VERSION}",
                        extra_payload={"server_version": PROTOCOL_VERSION}
                    ))
                    
            except Exception as e:
                try:
                    client_socket.send(build_packet(
                        "SERVER", "error",
                        f"Hatalı paket: {str(e)}",
                        error_code=0x0A
                    ))
                except:
                    pass
                    
    except:
        pass
    finally:
        with lock:
            userinfo = clients.pop(client_socket, None)
        client_socket.close()
        if userinfo:
            username = userinfo[0]
            broadcast(build_packet(
                "SERVER", "leave",
                f"{username} sohbetten ayrıldı"
            ))
            broadcast_user_list()
        print(f"[-] Bağlantı sonlandı: {client_address}")

def broadcast(message, exclude=None):
    """Mesajı tüm istemcilere ilet"""
    if exclude is None:
        exclude = []
    with lock:
        for client in list(clients.keys()):
            if client in exclude:
                continue
            try:
                client.send(message)
            except:
                pass

def broadcast_user_list():
    """Güncel kullanıcı listesini tüm istemcilere gönder"""
    with lock:
        user_list = [
            {
                "username": u,
                "ip": ip,
                "version": ver
            }
            for (_, (u, ip, ver)) in enumerate(clients.items())
        ]
        msg = build_packet(
            "SERVER", "userlist",
            extra_payload={
                "users": user_list,
                "server_version": PROTOCOL_VERSION,
                "min_version": MIN_SUPPORTED_VERSION
            }
        )
        for client in list(clients.keys()):
            try:
                client.send(msg)
            except:
                pass

def start_server():
    """TCP sunucusunu başlat"""
    global server_socket, is_running
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", 12345))
        server_socket.listen()
        is_running = True
        print(f"[*] TCP Sunucu başlatıldı - 0.0.0.0:12345")
        print(f"[*] Protokol v{PROTOCOL_VERSION} (Min: v{MIN_SUPPORTED_VERSION})")
        print(f"[*] Maksimum kullanıcı: {MAX_CLIENTS}")
        print(f"[*] Maksimum paket boyutu: {MAX_PACKET_SIZE} bytes")

        while is_running:
            try:
                server_socket.settimeout(1)  # 1 saniye timeout
                client_socket, client_address = server_socket.accept()
                thread = threading.Thread(target=handle_client, 
                                       args=(client_socket, client_address))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except:
                if is_running:  # Sadece beklenmeyen hataları göster
                    print("[!] Bağlantı kabul hatası")
                break
                
    except Exception as e:
        print(f"[!] Sunucu hatası: {e}")
    finally:
        stop_server(finally_call=True)

def stop_server(finally_call=False):
    """Sunucuyu güvenli bir şekilde durdur"""
    global server_socket, is_running
    
    is_running = False
    
    # Tüm istemcilere kapanış mesajı gönder
    with lock:
        for client in list(clients.keys()):
            try:
                client.send(build_packet(
                    "SERVER", "error",
                    "Sunucu kapatılıyor...",
                    error_code=0x0A
                ))
            except:
                pass
            try:
                client.close()
            except:
                pass
        clients.clear()
    
    # Sunucu soketini kapat
    if server_socket:
        try:
            server_socket.close()
        except:
            pass
        server_socket = None
    
    # Konsola sadece bir kez yazdır
    if not finally_call:
        print("[*] TCP Sunucu kapatıldı.")

if __name__ == "__main__":
    start_server()
