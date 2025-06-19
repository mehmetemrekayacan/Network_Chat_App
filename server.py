"""
Basit TCP Chat Sunucusu
- TCP üzerinde çoklu kullanıcı desteği
- Basit protokol kullanımı
"""
import socket
import threading
import json
import time
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES
)

MAX_CLIENTS = 10  # Maksimum kullanıcı sayısı
clients = {}  # {client_socket: (username, ip)}
lock = threading.Lock()
server_socket = None
is_running = False

# Sunucu mesaj queue'su - GUI için
server_message_queue = []
server_queue_lock = threading.Lock()

def handle_client(client_socket, client_address):
    """İstemci bağlantısını yönet"""
    print(f"[+] Yeni bağlantı: {client_address}")
    try:
        # İlk mesaj JOIN olmalı
        join_data = client_socket.recv(MAX_PACKET_SIZE)
        if not join_data:
            client_socket.close()
            return
            
        join_packet = parse_packet(join_data)
        if not join_packet:
            # Geçersiz paket
            try:
                client_socket.send(build_packet(
                    "SERVER", "message", "Geçersiz paket formatı"
                ))
            except:
                pass
            client_socket.close()
            return
            
        # JOIN mesajı kontrolü
        if join_packet["header"]["type"] != "join":
            try:
                client_socket.send(build_packet(
                    "SERVER", "message", "İlk mesaj JOIN olmalı"
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
                        "SERVER", "message", "Sunucu dolu"
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
                        "SERVER", "message", "Bu kullanıcı adı zaten kullanımda"
                    ))
                except:
                    pass
                client_socket.close()
                return
                
            clients[client_socket] = (username, client_address[0])
            
        # Kullanıcı listesi gönder
        broadcast_user_list()
        # Katılma mesajını yayınla
        broadcast(build_packet(
            "SERVER", "message", f"{username} sohbete katıldı"
        ), exclude=[client_socket])
                
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
                    # Sunucu GUI'si için queue'ya ekle
                    with server_queue_lock:
                        server_message_queue.append({
                            "type": "message",
                            "sender": sender,
                            "text": text,
                            "timestamp": time.time()
                        })
                    broadcast(build_packet(sender, "message", text))
                elif msg_type == "leave":
                    break
                elif msg_type == "ping":
                    # Ping'e pong ile yanıt
                    client_socket.send(build_packet("SERVER", "pong", "Pong"))
                    
            except Exception as e:
                print(f"[!] İstemci hatası: {e}")
                break
                    
    except:
        pass
    finally:
        with lock:
            userinfo = clients.pop(client_socket, None)
        client_socket.close()
        if userinfo:
            username = userinfo[0]
            broadcast(build_packet(
                "SERVER", "message", f"{username} sohbetten ayrıldı"
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
        user_list = [userinfo[0] for userinfo in clients.values()]
        msg = build_packet(
            "SERVER", "userlist",
            f"Bağlı kullanıcılar: {', '.join(user_list)}",
            extra={"users": user_list}
        )
        for client in list(clients.keys()):
            try:
                client.send(msg)
            except:
                pass
        
        # Sunucu GUI'si için de kullanıcı listesi güncellemesi ekle
        with server_queue_lock:
            server_message_queue.append({
                "type": "userlist",
                "users": user_list,
                "timestamp": time.time()
            })

def start_server_with_port(port=12345):
    """TCP sunucusunu belirtilen port ile başlat"""
    global server_socket, is_running
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", port))
        server_socket.listen()
        is_running = True
        print(f"[*] TCP Sunucu başlatıldı - 0.0.0.0:{port}")
        print(f"[*] Protokol v{PROTOCOL_VERSION}")
        print(f"[*] Maksimum kullanıcı: {MAX_CLIENTS}")

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
                if is_running:
                    print("[!] Bağlantı kabul hatası")
                break
                
    except Exception as e:
        print(f"[!] Sunucu hatası: {e}")
    finally:
        stop_server(finally_call=True)

def start_server():
    """TCP sunucusunu başlat (eski versiyon)"""
    start_server_with_port(12345)

def get_server_messages():
    """Sunucu GUI'si için bekleyen mesajları al"""
    with server_queue_lock:
        messages = server_message_queue.copy()
        server_message_queue.clear()
        return messages

def get_connected_users():
    """Sunucu GUI'si için bağlı kullanıcı listesini al"""
    with lock:
        return [userinfo[0] for userinfo in clients.values()]

def stop_server(finally_call=False):
    """Sunucuyu güvenli bir şekilde durdur"""
    global server_socket, is_running
    
    is_running = False
    
    # Tüm istemcilere kapanış mesajı gönder
    with lock:
        for client in list(clients.keys()):
            try:
                client.send(build_packet(
                    "SERVER", "message", "Sunucu kapatılıyor..."
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
    
    if not finally_call:
        print("[*] TCP Sunucu kapatıldı.")

if __name__ == "__main__":
    start_server()
