"""
TCP tabanlı chat sunucusu.
- Çok kullanıcılı, güvenilirlik mekanizmalı TCP chat sunucusu.
- Protokol: network/protocol.py
- Özellikler: kullanıcı listesi, bağlantı yönetimi, mesaj iletimi.
"""
import socket
import threading
import json
from datetime import datetime
from protocol import build_packet, parse_packet, PROTOCOL_VERSION, MAX_PACKET_SIZE

MAX_CLIENTS = 10  # Maksimum kullanıcı sayısı
clients = {}  # {client_socket: (username, ip)}
lock = threading.Lock()
server_socket = None
is_running = False

def handle_client(client_socket, client_address):
    print(f"[+] Yeni bağlantı: {client_address}")
    try:
        # İlk mesaj kullanıcı adı ve JOIN olmalı
        join_data = client_socket.recv(MAX_PACKET_SIZE)
        if not join_data:
            client_socket.close()
            return
            
        join_packet = parse_packet(join_data)
        if not join_packet or join_packet["header"]["type"] != "join":
            client_socket.close()
            return
            
        username = join_packet["header"]["sender"]
        
        with lock:
            if len(clients) >= MAX_CLIENTS:
                try:
                    client_socket.send(build_packet("error", "SERVER", 
                        "Sunucu dolu, daha fazla kullanıcı kabul edilmiyor."))
                except:
                    pass
                client_socket.close()
                print(f"[-] {client_address} reddedildi: Sunucu dolu.")
                return
            clients[client_socket] = (username, client_address[0])
            
        broadcast_user_list()
        broadcast(build_packet("join", username, f"{username} sohbete katıldı."), 
                exclude=[client_socket])
                
        while is_running:
            try:
                data = client_socket.recv(MAX_PACKET_SIZE)
                if not data:
                    break
                    
                packet = parse_packet(data)
                if not packet:
                    continue
                    
                msg_type = packet["header"]["type"]
                sender = packet["header"]["sender"]
                text = packet["payload"]["text"]
                
                if msg_type == "message":
                    display_msg = build_packet("message", sender, text)
                    broadcast(display_msg)
                elif msg_type == "leave":
                    break
                    
            except Exception as e:
                try:
                    client_socket.send(build_packet("error", "SERVER", f"Hatalı paket: {e}"))
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
            broadcast(build_packet("leave", username, f"{username} sohbetten ayrıldı."))
            broadcast_user_list()
        print(f"[-] Bağlantı sonlandı: {client_address}")

def broadcast(message, exclude=None):
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
    with lock:
        user_list = [
            {"username": u, "ip": ip}
            for (_, (u, ip)) in enumerate(clients.items())
        ]
        msg = build_packet("userlist", "SERVER", extra_payload={"users": user_list})
        for client in list(clients.keys()):
            try:
                client.send(msg)
            except:
                pass

def start_server():
    global server_socket, is_running
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", 12345))
        server_socket.listen()
        is_running = True
        print(f"[*] TCP Sunucu başlatıldı - 0.0.0.0:12345")
        print(f"[*] Protokol v{PROTOCOL_VERSION}, Maksimum kullanıcı: {MAX_CLIENTS}")

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
    global server_socket, is_running
    
    is_running = False
    
    # Tüm istemci bağlantılarını kapat
    with lock:
        for client in list(clients.keys()):
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
