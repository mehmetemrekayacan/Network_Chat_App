"""
UDP tabanlı chat sunucusu.
- Çok kullanıcılı, güvenilirlik mekanizmalı UDP chat sunucusu.
- Protokol: network/protocol.py (v1.2)
- Özellikler: pencere yönetimi, paket parçalama, RTT, bağlantı yönetimi, hata yönetimi.
"""
import socket
import threading
import time
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION, MIN_SUPPORTED_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, ERROR_CODES, version_compatible,
    fragmenter, window, RETRY_TIMEOUT, MAX_RETRIES
)

class UDPServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.sock = None
        self.clients = {}  # {addr: {"username": str, "version": str, "window": SlidingWindow, "last_seen": float}}
        self.running = False
        self.lock = threading.Lock()
        
    def start(self):
        """Sunucuyu başlat"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.running = True
        
        print(f"[*] UDP Sunucu başlatıldı - {self.host}:{self.port}")
        print(f"[*] Protokol v{PROTOCOL_VERSION} (Min: v{MIN_SUPPORTED_VERSION})")
        print(f"[*] Maksimum paket boyutu: {MAX_PACKET_SIZE} bytes")
        print(f"[*] Yeniden gönderim: {MAX_RETRIES} deneme, {RETRY_TIMEOUT}s timeout")
        
        # İstemci yönetimi thread'i
        threading.Thread(target=self.manage_clients, daemon=True).start()
        
        # Ana mesaj alma döngüsü
        while self.running:
            try:
                data, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                threading.Thread(target=self.handle_packet, args=(data, addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    print(f"[!] Paket alma hatası: {e}")
                    
    def stop(self):
        """Sunucuyu güvenli bir şekilde durdur"""
        if not self.running:
            return
            
        self.running = False
        
        # Tüm istemcilere kapanış mesajı gönder
        with self.lock:
            for addr, client in self.clients.items():
                try:
                    self.sock.sendto(build_packet(
                        "SERVER", "error",
                        "Sunucu kapatılıyor...",
                        error_code=0x0A
                    ), addr)
                except:
                    pass
                    
        # Soketi kapat
        if self.sock:
            self.sock.close()
            
        print("[*] UDP Sunucu kapatıldı")
        
    def manage_clients(self):
        """İstemci bağlantılarını yönet"""
        while self.running:
            try:
                # Bağlantısı kopan istemcileri temizle
                with self.lock:
                    current_time = time.time()
                    disconnected = []
                    
                    for addr, client in self.clients.items():
                        if current_time - client["last_seen"] > 30:  # 30 saniye timeout
                            disconnected.append(addr)
                            
                    for addr in disconnected:
                        username = self.clients[addr]["username"]
                        del self.clients[addr]
                        self.broadcast_message(
                            build_packet(
                                "SERVER", "leave",
                                f"{username} bağlantısı koptu (Timeout)",
                                error_code=0x07
                            )
                        )
                        
                time.sleep(5)  # Her 5 saniyede bir kontrol et
                
            except Exception as e:
                print(f"[!] İstemci yönetim hatası: {e}")
                
    def handle_packet(self, data, addr):
        """Gelen paketi işle"""
        try:
            packet = parse_packet(data)
            if not packet:
                # Geçersiz paket
                self.sock.sendto(build_packet(
                    "SERVER", "error",
                    "Geçersiz paket formatı",
                    error_code=0x01
                ), addr)
                return
                
            header = packet["header"]
            msg_type = header["type"]
            
            # Hata kodu kontrolü
            if "error_code" in header:
                error_code = header["error_code"]
                if error_code != 0x00:  # Başarılı değilse
                    username = self.clients.get(addr, {}).get("username", "Bilinmeyen")
                    print(f"[!] İstemci hatası ({username}): {ERROR_CODES.get(error_code, 'Bilinmeyen hata')}")
                    return
            
            # Versiyon kontrolü
            client_version = header["version"]
            if not version_compatible(client_version):
                self.sock.sendto(build_packet(
                    "SERVER", "error",
                    f"Protokol versiyonu uyumsuz. Sunucu: {PROTOCOL_VERSION}, İstemci: {client_version}",
                    error_code=0x02
                ), addr)
                return
            
            # RTT ölçümü için ping mesajı
            if msg_type == "ping":
                # Aynı ping_time ile pong cevabı gönder
                extra = packet["payload"].get("extra", {})
                pong_packet = build_packet(
                    "SERVER", "pong",
                    extra_payload=extra
                )
                self.sock.sendto(pong_packet, addr)
                return
                
            # ACK işleme
            if msg_type == "ack":
                with self.lock:
                    if addr in self.clients:
                        if "seq" in header:
                            self.clients[addr]["window"].mark_acked(header["seq"])
                return
                
            # Parça işleme
            if "fragment" in header:
                fragment_info = header["fragment"]
                fragment_id = fragment_info["id"]
                fragment_no = fragment_info.get("fragment_no", 0)
                total_fragments = fragment_info["total"]
                
                # Parçayı ekle ve tamamlanıp tamamlanmadığını kontrol et
                complete_data = fragmenter.add_fragment(
                    fragment_id, fragment_no, total_fragments,
                    packet["payload"]["data"]
                )
                
                if complete_data:
                    # Tamamlanan paketi işle
                    packet = parse_packet(complete_data)
                    if not packet:
                        self.sock.sendto(build_packet(
                            "SERVER", "error",
                            "Parça birleştirme hatası",
                            error_code=0x08
                        ), addr)
                        return
                    header = packet["header"]
                    msg_type = header["type"]
                else:
                    # Parça için ACK gönder
                    self.sock.sendto(build_packet(
                        "SERVER", "ack",
                        seq=header.get("seq"),
                        ack=header.get("seq")
                    ), addr)
                    return
                    
            # İstemci durumunu güncelle
            with self.lock:
                if addr not in self.clients:
                    if msg_type == "join":
                        username = header["sender"]
                        
                        # Kullanıcı adı kontrolü
                        if any(c["username"] == username for c in self.clients.values()):
                            self.sock.sendto(build_packet(
                                "SERVER", "error",
                                "Bu kullanıcı adı zaten kullanımda.",
                                error_code=0x0A
                            ), addr)
                            return
                            
                        self.clients[addr] = {
                            "username": username,
                            "version": client_version,
                            "window": window.SlidingWindow(),
                            "last_seen": time.time()
                        }
                        self.broadcast_message(
                            build_packet(
                                "SERVER", "join",
                                f"{username} katıldı (Protokol v{client_version})"
                            )
                        )
                        # Kullanıcı listesini gönder
                        self.send_user_list(addr)
                    return
                else:
                    self.clients[addr]["last_seen"] = time.time()
                    
            # Mesaj tipine göre işle
            if msg_type == "message":
                # Mesajı diğer istemcilere ilet
                self.broadcast_message(packet, exclude=addr)
            elif msg_type == "leave":
                # İstemciyi kaldır
                with self.lock:
                    if addr in self.clients:
                        username = self.clients[addr]["username"]
                        del self.clients[addr]
                        self.broadcast_message(
                            build_packet(
                                "SERVER", "leave",
                                f"{username} ayrıldı"
                            )
                        )
            elif msg_type == "version_check":
                # Versiyon kontrolü yanıtı
                self.sock.sendto(build_packet(
                    "SERVER", "version_check",
                    f"Sunucu protokol versiyonu: {PROTOCOL_VERSION}",
                    extra_payload={
                        "server_version": PROTOCOL_VERSION,
                        "min_version": MIN_SUPPORTED_VERSION
                    }
                ), addr)
                        
            # ACK gönder
            if "seq" in header:
                self.sock.sendto(build_packet(
                    "SERVER", "ack",
                    seq=header.get("seq"),
                    ack=header.get("seq")
                ), addr)
                
        except Exception as e:
            print(f"[!] Paket işleme hatası: {e}")
            try:
                self.sock.sendto(build_packet(
                    "SERVER", "error",
                    f"Paket işleme hatası: {str(e)}",
                    error_code=0x0A
                ), addr)
            except:
                pass
            
    def send_user_list(self, addr):
        """Belirli bir istemciye kullanıcı listesini gönder"""
        with self.lock:
            user_list = [
                {
                    "username": c["username"],
                    "version": c["version"]
                }
                for c in self.clients.values()
            ]
            msg = build_packet(
                "SERVER", "userlist",
                extra_payload={
                    "users": user_list,
                    "server_version": PROTOCOL_VERSION,
                    "min_version": MIN_SUPPORTED_VERSION
                }
            )
            try:
                self.sock.sendto(msg, addr)
            except:
                pass
            
    def broadcast_message(self, packet, exclude=None):
        """Mesajı tüm istemcilere ilet"""
        with self.lock:
            for addr, client in self.clients.items():
                if addr != exclude:
                    try:
                        # Pencere kontrolü
                        if not client["window"].can_send():
                            continue
                            
                        # Paketi pencereye ekle
                        seq = client["window"].add_packet(packet)
                        
                        # Paketi gönder
                        self.sock.sendto(packet, addr)
                        
                        # ACK bekle
                        start_time = time.time()
                        ack_received = False
                        
                        while time.time() - start_time < RETRY_TIMEOUT:
                            try:
                                self.sock.settimeout(RETRY_TIMEOUT - (time.time() - start_time))
                                data, ack_addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                                
                                if ack_addr == addr:
                                    ack_packet = parse_packet(data)
                                    if ack_packet and ack_packet["header"]["type"] == "ack":
                                        if "seq" in ack_packet["header"] and ack_packet["header"]["seq"] == seq:
                                            client["window"].mark_acked(seq)
                                            ack_received = True
                                            break
                                            
                            except socket.timeout:
                                break
                                
                        if not ack_received:
                            # Yeniden gönderim dene
                            retries = 0
                            while retries < MAX_RETRIES:
                                try:
                                    self.sock.sendto(packet, addr)
                                    time.sleep(0.1)  # Kısa bekleme
                                    
                                    # ACK kontrolü
                                    self.sock.settimeout(RETRY_TIMEOUT)
                                    data, ack_addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                                    
                                    if ack_addr == addr:
                                        ack_packet = parse_packet(data)
                                        if ack_packet and ack_packet["header"]["type"] == "ack":
                                            if "seq" in ack_packet["header"] and ack_packet["header"]["seq"] == seq:
                                                client["window"].mark_acked(seq)
                                                break
                                                
                                except:
                                    retries += 1
                                    if retries == MAX_RETRIES:
                                        print(f"[!] Mesaj iletilemedi ({client['username']}): Maksimum yeniden deneme sayısı aşıldı")
                                    
                    except Exception as e:
                        print(f"[!] Mesaj iletim hatası ({addr}): {e}")

if __name__ == "__main__":
    server = UDPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
