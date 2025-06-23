"""
Network Topology Discovery Modülü
- Basit peer-to-peer bağlantı keşfi
- RTT ölçümü ve peer durumu izleme
- Otomatik peer cleanup
"""
import socket
import threading
import time
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from protocol import build_packet, parse_packet, MESSAGE_TYPES

class NetworkTopologyDiscovery:
    def __init__(self):
        self.peers = {}  # {peer_id: {"ip": str, "port": int, "rtt": float, "last_seen": time}}
        self.discovery_port = 12347  # Topology discovery için ayrı port
        self.lock = threading.Lock()
        self.is_running = False
        self.sock = None
        
    def get_local_ips(self):
        """Yerel IP adreslerini al"""
        import socket
        local_ips = ["127.0.0.1", "localhost"]
        try:
            # Hostname'den IP al
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            local_ips.append(host_ip)
            
            # Network interface'lerden IP'leri al
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            local_ips.append(local_ip)
            s.close()
        except:
            pass
        return list(set(local_ips))

    def start_discovery(self, peer_id: str):
        """Topology discovery servisini başlat"""
        self.peer_id = peer_id
        self.is_running = True
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Sabit port kullan
            try:
                self.sock.bind(("0.0.0.0", self.discovery_port))
                print(f"[*] Discovery socket bind: 0.0.0.0:{self.discovery_port}")
            except OSError as e:
                print(f"[!] Port {self.discovery_port} kullanılamadı: {e}")
                # Alternatif port dene
                for port in range(self.discovery_port + 1, self.discovery_port + 10):
                    try:
                        self.sock.bind(("0.0.0.0", port))
                        self.discovery_port = port
                        print(f"[*] Discovery socket bind: 0.0.0.0:{port}")
                        break
                    except OSError:
                        continue
                else:
                    # Son çare: rastgele port
                    self.sock.bind(("0.0.0.0", 0))
                    self.discovery_port = self.sock.getsockname()[1]
                    print(f"[*] Discovery socket bind: 0.0.0.0:{self.discovery_port} (random)")
            
            # Discovery thread'lerini başlat
            threading.Thread(target=self.listen_discovery, daemon=True).start()
            threading.Thread(target=self.periodic_discovery, daemon=True).start()
            threading.Thread(target=self.rtt_measurement, daemon=True).start()
            
            print(f"[*] Network topology discovery başlatıldı - {peer_id} @ Port: {self.discovery_port}")
            
            # İlk announcement'ı hemen yap
            time.sleep(1)
            self.broadcast_announcement()
            
        except Exception as e:
            print(f"[!] Topology discovery başlatma hatası: {e}")
            self.is_running = False
    
    def stop_discovery(self):
        """Discovery servisini durdur"""
        self.is_running = False
        
        # KENDİ PEER LİSTESİNİ TEMİZLE
        with self.lock:
            peer_count = len(self.peers)
            if peer_count > 0:
                print(f"[CLEANUP] Kapatma sırasında {peer_count} peer temizleniyor...")
                self.peers.clear()
                print("[CLEANUP] Tüm peer'lar temizlendi")
        
        if self.sock:
            self.sock.close()
        print("[*] Network topology discovery durduruldu")
    
    def listen_discovery(self):
        """Discovery mesajlarını dinle"""
        print(f"[*] Discovery listener başlatıldı: {self.peer_id}")
        
        while self.is_running:
            try:
                self.sock.settimeout(2)
                data, addr = self.sock.recvfrom(2048)
                
                # Paket tipini hızlıca kontrol et
                try:
                    quick_check = json.loads(data.decode('utf-8'))
                    msg_type = quick_check.get("type", "unknown")
                    peer_id = quick_check.get("peer_id", "unknown")
                    
                    # Sadece önemli mesajları logla
                    if msg_type in ["ping_topology", "pong_topology"]:
                        timestamp = quick_check.get("timestamp", 0)
                        print(f"[{msg_type.upper()}] {peer_id} @ {addr} (ts: {timestamp:.3f})")
                    
                except:
                    print(f"[RX] Invalid packet from {addr}")
                    continue
                
                self.handle_discovery_packet(data, addr)
                
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
            except OSError as e:
                if e.winerror == 10054:  # Windows connection reset
                    continue
                if self.is_running:
                    print(f"[!] Discovery socket hatası: {e}")
                    time.sleep(1)
                    continue
            except Exception as e:
                if self.is_running:
                    print(f"[!] Discovery dinleme hatası: {e}")
                    time.sleep(1)
                    continue
    
    def handle_discovery_packet(self, data: bytes, addr: Tuple[str, int]):
        """Discovery paketini işle"""
        try:
            packet = json.loads(data.decode('utf-8'))
            msg_type = packet.get("type")
            peer_id = packet.get("peer_id")
            
            if msg_type == "peer_announce":
                self.handle_peer_announce(peer_id, addr, packet)
            elif msg_type == "peer_request":
                self.handle_peer_request(peer_id, addr)
            elif msg_type == "peer_list":
                self.handle_peer_list(peer_id, addr, packet)
            elif msg_type == "ping_topology":
                self.handle_ping_topology(peer_id, addr, packet)
            elif msg_type == "pong_topology":
                self.handle_pong_topology(peer_id, addr, packet)
                
        except json.JSONDecodeError as e:
            print(f"[!] JSON decode hatası: {e}")
        except Exception as e:
            print(f"[!] Discovery paket işleme hatası: {e}")
    
    def handle_peer_announce(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Peer duyurusunu işle"""
        print(f"[ANNOUNCE] {self.peer_id} <- {peer_id} from {addr}")
        
        # Kendi kendini eklemeyi önle
        if hasattr(self, 'peer_id') and peer_id == self.peer_id:
            print(f"[SKIP] Kendimizi eklemeyi atlıyoruz: {peer_id}")
            return
            
        with self.lock:
            # Eğer peer zaten varsa sadece güncelle
            if peer_id in self.peers:
                self.peers[peer_id]["last_seen"] = time.time()
                self.peers[peer_id]["ip"] = addr[0]
                self.peers[peer_id]["discovery_port"] = self.discovery_port
                print(f"[~] Peer yenilendi: {peer_id}")
            else:
                # Yeni peer ekle
                self.peers[peer_id] = {
                    "ip": addr[0],
                    "port": addr[1],
                    "discovery_port": self.discovery_port,
                    "rtt": 0.0,
                    "last_seen": time.time()
                }
                print(f"[+] Yeni peer keşfedildi: {peer_id} ({addr[0]}:{addr[1]})")
        
        # Kendi peer listesini gönder
        self.send_peer_list(addr)
        print(f"[TX] Peer listesi gönderildi: {peer_id} -> {len(self.peers)} peers")
        
        # YENI: Direkt geri announcement gönder (iki taraflı keşif için)
        self.send_direct_response_announcement(peer_id, addr)
    
    def send_direct_response_announcement(self, peer_id: str, addr: Tuple[str, int]):
        """Peer announcement'a karşılık direkt response gönder"""
        if not hasattr(self, 'peer_id'):
            return
            
        response_packet = {
            "type": "peer_announce",
            "peer_id": self.peer_id,
            "timestamp": time.time()
        }
        
        try:
            # Smart addressing uygula
            target_ip = addr[0]
            if target_ip.startswith("10.202.1.") or target_ip in self.get_local_ips():
                target_ip = "127.0.0.1"
            
            target_addr = (target_ip, addr[1])
            self.sock.sendto(json.dumps(response_packet).encode('utf-8'), target_addr)
            print(f"[RESPONSE ANNOUNCE] {self.peer_id} -> {peer_id} @ {target_addr}")
        except Exception as e:
            print(f"[!] Response announcement hatası ({peer_id}): {e}")
    
    def handle_peer_request(self, peer_id: str, addr: Tuple[str, int]):
        """Peer listesi isteğini işle"""
        self.send_peer_list(addr)
    
    def handle_peer_list(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Peer listesi paketini işle"""
        # Kendi kendimizden gelen listeyi yoksay
        if hasattr(self, 'peer_id') and peer_id == self.peer_id:
            return
            
        peer_list = packet.get("peers", [])
        
        with self.lock:
            for peer_info in peer_list:
                remote_peer_id = peer_info.get("peer_id")
                remote_ip = peer_info.get("ip")
                remote_port = peer_info.get("port")
                remote_rtt = peer_info.get("rtt", 0.0)
                
                # Kendi kendini eklemeyi önle
                if hasattr(self, 'peer_id') and remote_peer_id == self.peer_id:
                    continue
                
                # Eğer bu peer'i bilmiyorsak ekle
                if remote_peer_id not in self.peers:
                    self.peers[remote_peer_id] = {
                        "ip": remote_ip,
                        "port": remote_port,
                        "discovery_port": self.discovery_port,
                        "rtt": remote_rtt,
                        "last_seen": time.time()
                    }
                    print(f"[+] Peer listesinden eklendi: {remote_peer_id} ({remote_ip}:{remote_port})")
                else:
                    # Sadece son görülme zamanını güncelle
                    self.peers[remote_peer_id]["last_seen"] = time.time()
                    self.peers[remote_peer_id]["discovery_port"] = self.discovery_port
    
    def handle_ping_topology(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Topology ping'ini işle"""
        timestamp = packet.get("timestamp", time.time())
        ping_id = packet.get("ping_id", "unknown")
        print(f"[PING RX] {self.peer_id} <- {peer_id} from {addr} (ts: {timestamp:.3f}, id: {ping_id})")
        
        # Kendi kendine ping yanıtı verme
        if hasattr(self, 'peer_id') and peer_id == self.peer_id:
            print(f"[SKIP] Self-ping yanıtını atlıyoruz: {peer_id}")
            return
        
        # Pong gönder - Smart addressing
        pong_packet = {
            "type": "pong_topology",
            "peer_id": getattr(self, 'peer_id', 'unknown'),
            "timestamp": timestamp,
            "ping_id": ping_id,
            "response_time": time.time()
        }
        
        try:
            # Smart addressing: localhost detection
            response_addr = addr
            if addr[0].startswith("10.202.1.") or addr[0] in self.get_local_ips():
                response_addr = ("127.0.0.1", addr[1])
                
            print(f"[PONG TX] {self.peer_id} -> {peer_id} to {response_addr} (ts: {timestamp:.3f})")
            self.sock.sendto(json.dumps(pong_packet).encode('utf-8'), response_addr)
        except Exception as e:
            print(f"[!] Pong gönderme hatası: {e}")
    
    def handle_pong_topology(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Topology pong'unu işle ve RTT hesapla"""
        send_time = packet.get("timestamp", 0)
        ping_id = packet.get("ping_id", "unknown")
        current_time = time.time()
        rtt = (current_time - send_time) * 1000  # ms cinsinden
        
        print(f"[PONG RX] {self.peer_id} <- {peer_id} from {addr} (ts: {send_time:.3f}, id: {ping_id}, rtt: {rtt:.1f}ms)")
        
        # DÜZELTME: ping_id'ye göre kontrol et, peer_id'ye göre değil
        # Eğer ping_id bizim ID'mizle başlıyorsa, bu bizim ping'imize yanıt
        if not hasattr(self, 'peer_id'):
            print(f"[SKIP] Peer ID henüz ayarlanmadı")
            return
            
        if not ping_id.startswith(f"{self.peer_id}_"):
            print(f"[SKIP] Bu ping bizim değil: {ping_id} (bizim ID: {self.peer_id})")
            return
        
        print(f"[RTT CALC] {peer_id}: send_time={send_time:.3f}, current_time={current_time:.3f}, rtt={rtt:.1f}ms")
        
        with self.lock:
            if peer_id in self.peers:
                old_rtt = self.peers[peer_id].get("rtt", 0)
                self.peers[peer_id]["rtt"] = rtt
                self.peers[peer_id]["last_seen"] = current_time
                print(f"[RTT SUCCESS] ✅ {peer_id}: {rtt:.1f}ms (önceki: {old_rtt:.1f}ms)")
            else:
                available_peers = list(self.peers.keys())
                print(f"[!] ❌ Pong peer bulunamadı: {peer_id} (mevcut peers: {available_peers})")
                
                # Peer yoksa ekle (discovery'den kaçmış olabilir)
                self.peers[peer_id] = {
                    "ip": addr[0],
                    "port": addr[1],
                    "discovery_port": self.discovery_port,
                    "rtt": rtt,
                    "last_seen": current_time
                }
                print(f"[+] Pong'dan peer eklendi: {peer_id} @ {addr[0]}:{addr[1]} RTT: {rtt:.1f}ms")
    
    def send_peer_list(self, target_addr: Tuple[str, int]):
        """Peer listesini gönder"""
        with self.lock:
            peer_list = []
            for peer_id, info in self.peers.items():
                peer_list.append({
                    "peer_id": peer_id,
                    "ip": info["ip"],
                    "port": info["port"],
                    "rtt": info["rtt"]
                })
        
        packet = {
            "type": "peer_list",
            "peer_id": getattr(self, 'peer_id', 'unknown'),
            "peers": peer_list,
            "timestamp": time.time()
        }
        
        self.sock.sendto(json.dumps(packet).encode('utf-8'), target_addr)
    
    def periodic_discovery(self):
        """Periyodik peer keşfi"""
        announcement_counter = 0
        
        while self.is_running:
            try:
                # İlk 2 dakika daha sık broadcast yap
                if announcement_counter < 12:  # İlk 12 cycle (2 dakika)
                    self.broadcast_announcement()
                    print(f"[DISCOVERY] Cycle {announcement_counter+1}/12 - Initial discovery phase")
                elif announcement_counter % 6 == 0:  # Her 1 dakikada bir
                    self.broadcast_announcement()
                    print(f"[DISCOVERY] Maintenance broadcast - cycle {announcement_counter}")
                
                # Eski peer'ları temizle
                self.cleanup_old_peers()
                
                # Mevcut peer sayısını logla
                peer_count = len(self.peers)
                if peer_count > 0:
                    print(f"[DISCOVERY] Mevcut peer sayısı: {peer_count}")
                
                time.sleep(10)  # 10 saniyede bir
                announcement_counter += 1
                
            except Exception as e:
                print(f"[!] Periyodik discovery hatası: {e}")
    
    def broadcast_announcement(self):
        """Kendi varlığını duyur"""
        if not hasattr(self, 'peer_id'):
            return
            
        packet = {
            "type": "peer_announce",
            "peer_id": self.peer_id,
            "timestamp": time.time()
        }
        
        # 1. Broadcast gönder
        try:
            broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Broadcast gönder
            broadcast_sock.sendto(
                json.dumps(packet).encode('utf-8'), 
                ('<broadcast>', self.discovery_port)
            )
            
            # Localhost'a da gönder
            broadcast_sock.sendto(
                json.dumps(packet).encode('utf-8'), 
                ('127.0.0.1', self.discovery_port)
            )
                
            broadcast_sock.close()
            print(f"[BROADCAST] {self.peer_id} announced to network")
        except Exception as e:
            print(f"[!] Broadcast announcement hatası: {e}")
        
        # 2. YENI: Bilinen peer'lara direkt announcement gönder
        self.send_direct_announcements(packet)
    
    def send_direct_announcements(self, packet: dict):
        """Bilinen peer'lara direkt announcement gönder"""
        with self.lock:
            for peer_id, info in self.peers.items():
                if peer_id != self.peer_id:
                    try:
                        # Localhost detection için smart addressing
                        target_ip = info["ip"]
                        if target_ip.startswith("10.202.1.") or target_ip in self.get_local_ips():
                            target_ip = "127.0.0.1"
                        
                        target_addr = (target_ip, info["discovery_port"])
                        self.sock.sendto(json.dumps(packet).encode('utf-8'), target_addr)
                        print(f"[DIRECT ANNOUNCE] {self.peer_id} -> {peer_id} @ {target_addr}")
                    except Exception as e:
                        print(f"[!] Direct announcement hatası ({peer_id}): {e}")
    
    def rtt_measurement(self):
        """RTT ölçümü"""
        print(f"[RTT] RTT ölçümü 3 saniye sonra başlayacak...")
        time.sleep(3)
        
        while self.is_running:
            try:
                with self.lock:
                    peers_to_ping = list(self.peers.items())
                
                if peers_to_ping:
                    print(f"[RTT] {len(peers_to_ping)} peer'a ping gönderiliyor...")
                
                ping_count = 0
                for peer_id, info in peers_to_ping:
                    # Son 1 dakikada aktif olan peer'lara ping gönder
                    last_seen_diff = time.time() - info["last_seen"]
                    if last_seen_diff < 60:
                        discovery_port = info.get("discovery_port", self.discovery_port)
                        peer_ip = info["ip"]
                        
                        # Localhost detection
                        local_ips = self.get_local_ips()
                        if peer_ip in local_ips or peer_ip.startswith("10.202.1."):
                            target_addr = ("127.0.0.1", discovery_port)
                            print(f"[RTT] Localhost ping: {peer_id} @ {target_addr} (original: {peer_ip})")
                        else:
                            target_addr = (peer_ip, discovery_port)
                            print(f"[RTT] Remote ping: {peer_id} @ {target_addr}")
                        
                        self.ping_peer(peer_id, target_addr)
                        ping_count += 1
                    else:
                        print(f"[RTT] {peer_id} çok eski ({last_seen_diff:.0f}s), ping gönderilmiyor")
                
                if ping_count > 0:
                    print(f"[RTT] Toplam {ping_count} ping gönderildi, pong'lar bekleniyor...")
                
                time.sleep(5)  # 5 saniyede bir ping
                
            except Exception as e:
                print(f"[!] RTT ölçümü hatası: {e}")
    
    def ping_peer(self, peer_id: str, addr: Tuple[str, int]):
        """Peer'a ping gönder"""
        if not hasattr(self, 'peer_id'):
            return
        
        # Kendi kendine ping göndermek yasak
        if peer_id == self.peer_id:
            print(f"[SKIP] Self-ping engellendi: {peer_id}")
            return
            
        timestamp = time.time()
        packet = {
            "type": "ping_topology",
            "peer_id": self.peer_id,
            "timestamp": timestamp,
            "ping_id": f"{self.peer_id}_{timestamp:.3f}"
        }
        
        try:
            self.sock.sendto(json.dumps(packet).encode('utf-8'), addr)
            print(f"[PING TX] {self.peer_id} -> {peer_id} @ {addr} (timestamp: {timestamp:.3f})")
        except Exception as e:
            print(f"[!] Ping gönderme hatası ({peer_id}): {e}")
    
    def cleanup_old_peers(self):
        """Eski peer'ları temizle"""
        current_time = time.time()
        timeout = 20  # 20 saniye timeout
        
        with self.lock:
            expired_peers = []
            for peer_id, info in self.peers.items():
                age = current_time - info["last_seen"]
                if age > timeout:
                    expired_peers.append((peer_id, age))
            
            for peer_id, age in expired_peers:
                print(f"[-] Peer timeout: {peer_id} (last_seen: {age:.1f}s ago)")
                del self.peers[peer_id]
                        
            if expired_peers:
                remaining_peers = list(self.peers.keys())
                print(f"[CLEANUP] Kalan peer'lar: {remaining_peers}")
    
    def get_network_topology(self) -> Dict:
        """Mevcut network topology'sini döndür - BASİTLEŞTİRİLDİ"""
        with self.lock:
            return {
                "peers": dict(self.peers),
                "local_peer": getattr(self, 'peer_id', 'Henüz başlatılmadı'),
                "total_peers": len(self.peers),
                "discovery_time": datetime.now().isoformat()
            }
    
    def get_peer_list(self) -> List[Dict]:
        """Aktif peer listesini döndür"""
        with self.lock:
            return [
                {
                    "peer_id": peer_id,
                    "ip": info["ip"],
                    "port": info["port"],
                    "rtt": info["rtt"],
                    "status": "active" if (time.time() - info["last_seen"]) < 30 else "inactive"
                }
                for peer_id, info in self.peers.items()
            ]

# Global topology discovery instance
topology_discovery = NetworkTopologyDiscovery() 