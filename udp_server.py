"""
Basit UDP Chat Sunucusu
- UDP üzerinde güvenilir mesaj iletimi
- Sequence number ile sıralama 
- ACK ile onaylama
- Timeout ile yeniden gönderim
"""
import socket
import threading
import time
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, RETRY_TIMEOUT, MAX_RETRIES,
    sequencer
)

class UDPServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.sock = None
        self.is_running = False
        
        # Basit kullanıcı yönetimi
        self.clients = {}  # {addr: {"username": str, "last_seen": time}}
        self.lock = threading.Lock()
        
        # Basit güvenilirlik 
        self.pending_messages = {}  # {(addr, seq): {"packet": bytes, "timestamp": time, "retries": int}}
        
    def start(self):
        """UDP sunucuyu başlat"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            self.is_running = True
            
            print(f"[*] UDP Sunucu başlatıldı: {self.host}:{self.port}")
            print(f"[*] Protokol v{PROTOCOL_VERSION}")
            
            # Thread'leri başlat
            threading.Thread(target=self.listen_loop, daemon=True).start()
            threading.Thread(target=self.retry_loop, daemon=True).start()
            threading.Thread(target=self.cleanup_loop, daemon=True).start()
            
            # Ana döngü
            while self.is_running:
                time.sleep(1)
                
        except Exception as e:
            print(f"[!] UDP Sunucu hatası: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Sunucuyu durdur"""
        self.is_running = False
        if self.sock:
            self.sock.close()
        print("[*] UDP Sunucu durduruldu")
    
    def listen_loop(self):
        """Gelen mesajları dinle"""
        while self.is_running:
            try:
                data, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                self.handle_packet(data, addr)
            except Exception as e:
                if self.is_running:
                    print(f"[!] Dinleme hatası: {e}")
    
    def handle_packet(self, data, addr):
        """Gelen paketi işle"""
        packet = parse_packet(data)
        if not packet:
            return
            
        msg_type = packet["header"]["type"]
        sender = packet["header"]["sender"]
        text = packet["payload"]["text"]
        seq = packet["header"].get("seq")
        
        # ACK paketi mi?
        if msg_type == "ack":
            self.handle_ack(addr, seq)
            return
        
        # Sequence number varsa ACK gönder
        if seq is not None:
            ack_packet = build_packet("SERVER", "ack", seq=seq)
            self.sock.sendto(ack_packet, addr)
        
        # Duplicate kontrolü
        if seq is not None and sequencer.is_duplicate(seq):
            return  # Duplicate paket, yoksay
            
        # Mesaj tipine göre işle
        if msg_type == "join":
            self.handle_join(addr, sender)
        elif msg_type == "message":
            self.broadcast_message(packet, addr)
        elif msg_type == "private_message":
            self.handle_private_message(packet, addr)
        elif msg_type == "leave":
            self.handle_leave(addr, sender)
        elif msg_type == "ping":
            self.handle_ping(addr, sender)
            
        # Son görülme zamanını güncelle
        with self.lock:
            if addr in self.clients:
                self.clients[addr]["last_seen"] = time.time()
    
    def handle_join(self, addr, username):
        """Kullanıcı katılımını işle"""
        with self.lock:
            # Username çakışması kontrolü
            for client_info in self.clients.values():
                if client_info["username"] == username:
                    error_packet = build_packet("SERVER", "message", 
                                               f"Kullanıcı adı '{username}' zaten kullanımda")
                    self.reliable_send(error_packet, addr)
                    return
            
            # Kullanıcıyı ekle
            self.clients[addr] = {
                "username": username,
                "last_seen": time.time()
            }
        
        # Katılım mesajını yayınla
        join_msg = build_packet("SERVER", "message", 
                               f"{username} sohbete katıldı")
        self.broadcast_to_all(join_msg, exclude=[addr])
        
        # Kullanıcı listesini gönder
        self.send_user_list(addr)
        
        print(f"[+] Kullanıcı katıldı: {username} ({addr})")
    
    def handle_leave(self, addr, username):
        """Kullanıcı ayrılımını işle"""
        with self.lock:
            if addr in self.clients:
                del self.clients[addr]
        
        # Ayrılma mesajını yayınla
        leave_msg = build_packet("SERVER", "message", 
                                f"{username} sohbetten ayrıldı")
        self.broadcast_to_all(leave_msg, exclude=[addr])
        
        print(f"[-] Kullanıcı ayrıldı: {username} ({addr})")
    
    def handle_ping(self, addr, sender):
        """Ping'e pong ile yanıt ver"""
        pong_packet = build_packet("SERVER", "pong", f"Pong {sender}")
        self.reliable_send(pong_packet, addr)
    
    def handle_private_message(self, packet, sender_addr):
        """Private mesajı işle ve hedef kullanıcıya ilet"""
        sender = packet["header"]["sender"]
        text = packet["payload"]["text"]
        
        # Parse target user from message (@username: message)
        if text.startswith("@") and ":" in text:
            try:
                target_part, message_part = text.split(":", 1)
                target_user = target_part[1:].strip()  # Remove @
                message = message_part.strip()
                
                # Find target user's address - önce UDP clients'ta ara
                target_addr = None
                with self.lock:
                    for addr, client_info in self.clients.items():
                        if client_info["username"] == target_user:
                            target_addr = addr
                            break
                
                # UDP clients'ta bulunamazsa, TCP server'ın kullanıcı listesini kontrol et
                if not target_addr:
                    try:
                        import server
                        tcp_users = server.get_connected_users()
                        if target_user in tcp_users:
                            # Hedef kullanıcı TCP'de var ama UDP'de yok
                            # Mesajı sadece gönderene confirm olarak gönder
                            confirm_packet = build_packet("SERVER", "message", 
                                                        f"Private mesaj {target_user} kullanıcısına TCP üzerinden iletildi")
                            self.reliable_send(confirm_packet, sender_addr)
                            print(f"[Private] {sender} -> {target_user}: {message} (TCP user)")
                            return
                    except:
                        pass
                
                if target_addr:
                    # Send private message to target user (UDP'de bağlı)
                    private_packet = build_packet(sender, "private_message", 
                                                f"[Private from {sender}] {message}")
                    self.reliable_send(private_packet, target_addr)
                    
                    # Send confirmation to sender
                    confirm_packet = build_packet("SERVER", "message", 
                                                f"Private mesaj {target_user} kullanıcısına iletildi")
                    self.reliable_send(confirm_packet, sender_addr)
                    
                    print(f"[Private] {sender} -> {target_user}: {message}")
                else:
                    # Target user not found anywhere
                    error_packet = build_packet("SERVER", "message", 
                                               f"Kullanıcı '{target_user}' çevrimiçi değil")
                    self.reliable_send(error_packet, sender_addr)
                    
            except Exception as e:
                error_packet = build_packet("SERVER", "message", 
                                           f"Private mesaj hatası: {e}")
                self.reliable_send(error_packet, sender_addr)
        else:
            error_packet = build_packet("SERVER", "message", 
                                       "Private mesaj formatı hatalı. Doğru format: @username: mesaj")
            self.reliable_send(error_packet, sender_addr)
    
    def handle_ack(self, addr, seq):
        """ACK mesajını işle"""
        key = (addr, seq)
        if key in self.pending_messages:
            del self.pending_messages[key]
    
    def broadcast_message(self, packet, sender_addr):
        """Mesajı tüm istemcilere yayınla"""
        self.broadcast_to_all(packet, exclude=[sender_addr])
    
    def broadcast_to_all(self, packet_data, exclude=None):
        """Tüm bağlı istemcilere mesaj gönder"""
        if exclude is None:
            exclude = []
            
        with self.lock:
            for addr in list(self.clients.keys()):
                if addr not in exclude:
                    self.reliable_send(packet_data, addr)
    
    def send_user_list(self, addr):
        """Kullanıcı listesini gönder"""
        with self.lock:
            users = [info["username"] for info in self.clients.values()]
        
        user_list_packet = build_packet("SERVER", "userlist", 
                                       f"Bağlı kullanıcılar: {', '.join(users)}",
                                       extra={"users": users})
        self.reliable_send(user_list_packet, addr)
    
    def reliable_send(self, packet_data, addr):
        """Güvenilir mesaj gönderimi (ACK bekleyerek)"""
        if isinstance(packet_data, dict):
            # Dict ise encode et
            packet_data = build_packet(
                packet_data["header"]["sender"],
                packet_data["header"]["type"], 
                packet_data["payload"]["text"],
                extra=packet_data["payload"].get("extra")
            )
        
        # Sequence number ekle
        seq = sequencer.get_next_seq()
        packet = parse_packet(packet_data)
        packet["header"]["seq"] = seq
        final_packet = build_packet(
            packet["header"]["sender"],
            packet["header"]["type"],
            packet["payload"]["text"],
            seq=seq,
            extra=packet["payload"].get("extra")
        )
        
        # Paketi gönder
        try:
            self.sock.sendto(final_packet, addr)
            
            # Pending listesine ekle
            key = (addr, seq)
            self.pending_messages[key] = {
                "packet": final_packet,
                "timestamp": time.time(),
                "retries": 0
            }
        except Exception as e:
            print(f"[!] Gönderim hatası: {e}")
    
    def retry_loop(self):
        """Timeout olan mesajları yeniden gönder"""
        while self.is_running:
            current_time = time.time()
            
            # Pending mesajları kontrol et
            for key, msg_info in list(self.pending_messages.items()):
                age = current_time - msg_info["timestamp"]
                
                if age > RETRY_TIMEOUT:
                    if msg_info["retries"] < MAX_RETRIES:
                        # Yeniden gönder
                        addr, seq = key
                        try:
                            self.sock.sendto(msg_info["packet"], addr)
                            self.pending_messages[key]["timestamp"] = current_time
                            self.pending_messages[key]["retries"] += 1
                            print(f"[R] Yeniden gönderim: {addr}, seq={seq}, retry={msg_info['retries']}")
                        except:
                            pass
                    else:
                        # Maksimum deneme aşıldı
                        del self.pending_messages[key]
                        print(f"[!] Mesaj gönderimi başarısız: {key}")
            
            time.sleep(0.5)  # 500ms kontrol aralığı
    
    def cleanup_loop(self):
        """Eski kullanıcıları temizle"""
        while self.is_running:
            current_time = time.time()
            timeout = 60  # 60 saniye timeout
            
            with self.lock:
                expired_clients = []
                for addr, client_info in self.clients.items():
                    if current_time - client_info["last_seen"] > timeout:
                        expired_clients.append(addr)
                
                for addr in expired_clients:
                    username = self.clients[addr]["username"]
                    del self.clients[addr]
                    print(f"[T] Timeout: {username} ({addr})")
            
            time.sleep(30)  # 30 saniyede bir kontrol

if __name__ == "__main__":
    server = UDPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Sunucu kapatılıyor...")
        server.stop()
