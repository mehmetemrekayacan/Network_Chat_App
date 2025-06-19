"""
Network Topology Discovery Modülü
- Peer-to-peer bağlantı keşfi
- Network haritası çıkarma
- RTT ölçümü ve network analizi
- Bağlantı durumu izleme
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
        self.connections = {}  # {(peer1, peer2): {"established": bool, "rtt": float}}
        self.network_map = {}  # Network haritası
        self.discovery_port = 12346  # Topology discovery için ayrı port
        self.lock = threading.Lock()
        self.is_running = False
        self.sock = None
        
    def start_discovery(self, peer_id: str):
        """Topology discovery servisini başlat"""
        self.peer_id = peer_id
        self.is_running = True
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Boş port bul
            for port in range(self.discovery_port, self.discovery_port + 100):
                try:
                    self.sock.bind(("0.0.0.0", port))
                    self.discovery_port = port
                    break
                except OSError:
                    continue
            else:
                # Rastgele port kullan
                self.sock.bind(("0.0.0.0", 0))
                self.discovery_port = self.sock.getsockname()[1]
            
            # Discovery thread'lerini başlat
            threading.Thread(target=self.listen_discovery, daemon=True).start()
            threading.Thread(target=self.periodic_discovery, daemon=True).start()
            threading.Thread(target=self.rtt_measurement, daemon=True).start()
            
            print(f"[*] Network topology discovery başlatıldı - Port: {self.discovery_port}")
            
        except Exception as e:
            print(f"[!] Topology discovery başlatma hatası: {e}")
            self.is_running = False
    
    def stop_discovery(self):
        """Discovery servisini durdur"""
        self.is_running = False
        if self.sock:
            self.sock.close()
        print("[*] Network topology discovery durduruldu")
    
    def listen_discovery(self):
        """Discovery mesajlarını dinle"""
        while self.is_running:
            try:
                self.sock.settimeout(2)  # 2 saniye timeout
                data, addr = self.sock.recvfrom(1024)
                self.handle_discovery_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"[!] Discovery dinleme hatası: {e}")
                    break
    
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
            elif msg_type == "ping_topology":
                self.handle_ping_topology(peer_id, addr, packet)
            elif msg_type == "pong_topology":
                self.handle_pong_topology(peer_id, addr, packet)
            elif msg_type == "network_map":
                self.handle_network_map(packet)
                
        except Exception as e:
            print(f"[!] Discovery paket işleme hatası: {e}")
    
    def handle_peer_announce(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Peer duyurusunu işle"""
        with self.lock:
            self.peers[peer_id] = {
                "ip": addr[0],
                "port": addr[1],
                "rtt": 0.0,
                "last_seen": time.time(),
                "connections": packet.get("connections", [])
            }
        
        # Kendi peer listesini gönder
        self.send_peer_list(addr)
        print(f"[+] Yeni peer keşfedildi: {peer_id} ({addr[0]}:{addr[1]})")
    
    def handle_peer_request(self, peer_id: str, addr: Tuple[str, int]):
        """Peer listesi isteğini işle"""
        self.send_peer_list(addr)
    
    def handle_ping_topology(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Topology ping'ini işle"""
        timestamp = packet.get("timestamp", time.time())
        
        # Pong gönder
        pong_packet = {
            "type": "pong_topology",
            "peer_id": self.peer_id,
            "timestamp": timestamp,
            "response_time": time.time()
        }
        
        self.sock.sendto(json.dumps(pong_packet).encode('utf-8'), addr)
    
    def handle_pong_topology(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """Topology pong'unu işle ve RTT hesapla"""
        send_time = packet.get("timestamp", 0)
        rtt = (time.time() - send_time) * 1000  # ms cinsinden
        
        with self.lock:
            if peer_id in self.peers:
                self.peers[peer_id]["rtt"] = rtt
                self.peers[peer_id]["last_seen"] = time.time()
    
    def handle_network_map(self, packet: dict):
        """Network haritası güncellemesini işle"""
        remote_map = packet.get("network_map", {})
        
        with self.lock:
            # Kendi haritamızla birleştir
            for peer, connections in remote_map.items():
                if peer not in self.network_map:
                    self.network_map[peer] = connections
                else:
                    # Mevcut bağlantıları güncelle
                    self.network_map[peer].update(connections)
    
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
            "peer_id": self.peer_id,
            "peers": peer_list,
            "timestamp": time.time()
        }
        
        self.sock.sendto(json.dumps(packet).encode('utf-8'), target_addr)
    
    def periodic_discovery(self):
        """Periyodik peer keşfi"""
        while self.is_running:
            try:
                # Broadcast announcement
                self.broadcast_announcement()
                
                # Eski peer'ları temizle
                self.cleanup_old_peers()
                
                # Network haritasını güncelle
                self.update_network_map()
                
                time.sleep(30)  # 30 saniyede bir
                
            except Exception as e:
                print(f"[!] Periyodik discovery hatası: {e}")
    
    def broadcast_announcement(self):
        """Kendi varlığını duyur"""
        packet = {
            "type": "peer_announce",
            "peer_id": self.peer_id,
            "timestamp": time.time(),
            "connections": list(self.peers.keys())
        }
        
        # Broadcast gönder
        try:
            broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_sock.sendto(
                json.dumps(packet).encode('utf-8'), 
                ('<broadcast>', self.discovery_port)
            )
            broadcast_sock.close()
        except Exception as e:
            print(f"[!] Broadcast announcement hatası: {e}")
    
    def rtt_measurement(self):
        """RTT ölçümü"""
        while self.is_running:
            try:
                with self.lock:
                    peers_to_ping = list(self.peers.items())
                
                for peer_id, info in peers_to_ping:
                    if time.time() - info["last_seen"] < 60:  # Son 1 dakikada aktif
                        self.ping_peer(peer_id, (info["ip"], info["port"]))
                
                time.sleep(10)  # 10 saniyede bir ping
                
            except Exception as e:
                print(f"[!] RTT ölçümü hatası: {e}")
    
    def ping_peer(self, peer_id: str, addr: Tuple[str, int]):
        """Peer'a ping gönder"""
        packet = {
            "type": "ping_topology",
            "peer_id": self.peer_id,
            "timestamp": time.time()
        }
        
        try:
            self.sock.sendto(json.dumps(packet).encode('utf-8'), addr)
        except Exception as e:
            print(f"[!] Ping gönderme hatası ({peer_id}): {e}")
    
    def cleanup_old_peers(self):
        """Eski peer'ları temizle"""
        current_time = time.time()
        timeout = 120  # 2 dakika timeout
        
        with self.lock:
            expired_peers = []
            for peer_id, info in self.peers.items():
                if current_time - info["last_seen"] > timeout:
                    expired_peers.append(peer_id)
            
            for peer_id in expired_peers:
                del self.peers[peer_id]
                print(f"[-] Peer timeout: {peer_id}")
    
    def update_network_map(self):
        """Network haritasını güncelle"""
        with self.lock:
            # Kendi bağlantılarını haritaya ekle
            self.network_map[self.peer_id] = {
                peer_id: {
                    "rtt": info["rtt"],
                    "direct": True,
                    "last_seen": info["last_seen"]
                }
                for peer_id, info in self.peers.items()
            }
    
    def get_network_topology(self) -> Dict:
        """Mevcut network topology'sini döndür"""
        with self.lock:
            return {
                "peers": dict(self.peers),
                "network_map": dict(self.network_map),
                "local_peer": self.peer_id,
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
                    "status": "active" if (time.time() - info["last_seen"]) < 60 else "inactive"
                }
                for peer_id, info in self.peers.items()
            ]
    
    def find_shortest_path(self, target_peer: str) -> Optional[List[str]]:
        """Hedef peer'a en kısa yolu bul (basit dijkstra)"""
        if target_peer not in self.network_map:
            return None
        
        # Basit BFS ile en kısa yol
        queue = [(self.peer_id, [self.peer_id])]
        visited = set()
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target_peer:
                return path
            
            if current in visited:
                continue
            
            visited.add(current)
            
            # Komşuları ekle
            if current in self.network_map:
                for neighbor in self.network_map[current]:
                    if neighbor not in visited:
                        queue.append((neighbor, path + [neighbor]))
        
        return None

# Global topology discovery instance
topology_discovery = NetworkTopologyDiscovery() 