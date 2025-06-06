"""
P2P ağ düğümü modülü.
- Doğrudan düğümler arası iletişim desteği
- Ağ durumu izleme ve RTT ölçümü
- Dinamik bağlantı yönetimi
- Güvenilir mesaj iletimi
"""
import socket
import threading
import time
import json
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, ERROR_CODES
)
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import messagebox
import queue
import logging
from dataclasses import dataclass

@dataclass
class PeerInfo:
    """Peer bilgilerini saklayan veri sınıfı"""
    peer_id: str
    username: str
    host: str
    port: int
    last_seen: float
    rtt: float = 0.0
    is_active: bool = True
    packet_sent: int = 0
    packet_received: int = 0

class P2PNode:
    def __init__(self, host: str = "localhost", port: int = 0, username: str = None):
        self.host = host
        self.port = port
        self.username = username or "Anonim"
        self.socket = None
        
        # Bağlantı yönetimi
        self.peers: Dict[str, PeerInfo] = {}  # {username: (host, port)}
        self.connections: Dict[str, float] = {}  # {peer_id: last_seen}
        self.rtt_measurements: Dict[str, List[float]] = {}  # {peer_id: [rtt1, rtt2, ...]}
        
        # Ağ topolojisi
        self.network_graph = nx.Graph()
        self.network_graph.add_node(self.username)
        
        # Thread'ler
        self.is_running = False
        self.receiver_thread = None
        self.monitor_thread = None
        self.visualization_thread = None
        
        # Kilitler
        self.peers_lock = threading.Lock()
        self.graph_lock = threading.Lock()
        
        # Ağ haritası için Tkinter penceresi
        self.network_window = None
        self.network_canvas = None
        self.network_figure = None
        self.network_ax = None
        self.is_visualization_running = False
        
        # Görselleştirme güncellemeleri için kuyruk
        self.visualization_queue = queue.Queue()
        
    def start(self):
        """P2P düğümünü başlat"""
        if self.is_running:
            return
            
        self.is_running = True
        self.is_visualization_running = True
        
        # UDP soketini başlat
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        
        # Gerçek port numarasını al
        if self.port == 0:
            self.port = self.socket.getsockname()[1]
            
        print(f"[+] P2P düğümü başlatıldı: {self.host}:{self.port}")
        
        # Thread'leri başlat
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Ağ haritası görselleştirmesini başlat
        self.visualization_thread = threading.Thread(target=self._visualization_loop, daemon=True)
        self.visualization_thread.start()
        
    def stop(self):
        """P2P düğümünü durdur"""
        self.is_running = False
        self.is_visualization_running = False
        
        if self.socket:
            self.socket.close()
            
        if self.network_window:
            self.network_window.quit()
            self.network_window.destroy()
            self.network_window = None
        
    def connect_to_peer(self, peer_host: str, peer_port: int, peer_username: str) -> bool:
        """Yeni bir eş düğüme bağlan"""
        # Host adresini normalize et
        if peer_host == "localhost":
            peer_host = "127.0.0.1"
        
        # Kendine bağlanmayı engelle
        if peer_host in ["127.0.0.1", self.host] and peer_port == self.port:
            print(f"[!] Kendine bağlanma girişimi engellendi: {peer_host}:{peer_port}")
            return False
        
        # Zaten bağlı mı kontrol et
        with self.peers_lock:
            for peer_info in self.peers.values():
                # Host adreslerini normalize ederek karşılaştır
                normalized_peer_host = "127.0.0.1" if peer_info.host == "localhost" else peer_info.host
                if normalized_peer_host == peer_host and peer_info.port == peer_port:
                    print(f"[!] Bu peer'a zaten bağlı: {peer_host}:{peer_port}")
                    return True
        
        try:
            print(f"[+] P2P bağlantısı deneniyor: {peer_host}:{peer_port}")
            
            # Bağlantı isteği gönder
            connect_packet = build_packet(
                self.username, "p2p_connect",
                extra_payload={
                    "host": self.host,
                    "port": self.port,
                    "username": self.username
                }
            )
            self.socket.sendto(connect_packet, (peer_host, peer_port))
            
            # Yanıt bekleme - non-blocking approach
            success = False
            
            # Accept yanıtını bekle (maksimum 3 saniye)
            max_wait_time = 3.0
            check_interval = 0.1
            elapsed = 0.0
            
            while elapsed < max_wait_time:
                time.sleep(check_interval)
                elapsed += check_interval
                
                # Peer'ın eklenmişmi kontrol et (diğer thread tarafından eklenmiş olabilir)
                with self.peers_lock:
                    for peer_info in self.peers.values():
                        # Host adreslerini normalize ederek karşılaştır
                        normalized_peer_host = "127.0.0.1" if peer_info.host == "localhost" else peer_info.host
                        if normalized_peer_host == peer_host and peer_info.port == peer_port:
                            print(f"[+] P2P bağlantısı başarılı: {peer_info.username}@{peer_host}:{peer_port}")
                            return True
            
            # Timeout sonrası son kontrol
            with self.peers_lock:
                for peer_info in self.peers.values():
                    # Host adreslerini normalize ederek karşılaştır
                    normalized_peer_host = "127.0.0.1" if peer_info.host == "localhost" else peer_info.host
                    if normalized_peer_host == peer_host and peer_info.port == peer_port:
                        print(f"[+] P2P bağlantısı gecikmeli başarılı: {peer_info.username}@{peer_host}:{peer_port}")
                        return True
                
        except Exception as e:
            print(f"[!] P2P bağlantı hatası: {e}")
        finally:
            self.socket.settimeout(None)
        
        print(f"[!] P2P bağlantısı başarısız: {peer_host}:{peer_port}")
        return False
        
    def disconnect_from_peer(self, peer_username: str):
        """Eş düğümden ayrıl"""
        with self.peers_lock:
            if peer_username in self.peers:
                peer_info = self.peers[peer_username]
                try:
                    # Ayrılma mesajı gönder
                    disconnect_packet = build_packet(
                        self.username, "p2p_disconnect",
                        extra_payload={"username": self.username}
                    )
                    self.socket.sendto(disconnect_packet, (peer_info.host, peer_info.port))
                except:
                    pass
                    
                # Bağlantıyı temizle
                del self.peers[peer_username]
                del self.connections[peer_username]
                if peer_username in self.rtt_measurements:
                    del self.rtt_measurements[peer_username]
                    
                with self.graph_lock:
                    # Graf'tan bağlantıyı kaldır
                    for edge in list(self.network_graph.edges()):
                        if peer_username in edge[1]:
                            self.network_graph.remove_edge(*edge)
                            
    def send_to_peer(self, peer_username: str, message: str) -> bool:
        """Eş düğüme mesaj gönder"""
        with self.peers_lock:
            if peer_username not in self.peers:
                return False
                
            peer_info = self.peers[peer_username]
            try:
                packet = build_packet(self.username, "p2p_message", message)
                self.socket.sendto(packet, (peer_info.host, peer_info.port))
                return True
            except:
                return False
                
    def broadcast_message(self, message: str, exclude: list = None) -> int:
        """Tüm eş düğümlere mesaj gönder"""
        if not self.is_running or not self.socket:
            print("[!] P2P düğümü çalışmıyor, mesaj gönderilemedi")
            return 0
            
        if exclude is None:
            exclude = []
            
        sent_count = 0
        
        # Peer listesinin kopyasını al (thread safety için)
        peers_copy = {}
        with self.peers_lock:
            peers_copy = {peer: peer_info for peer, peer_info in self.peers.items()}
        
        # Her peer'a mesaj gönder
        for peer, peer_info in peers_copy.items():
            if peer not in exclude:
                try:
                    if hasattr(peer_info, 'host') and hasattr(peer_info, 'port'):
                        packet = build_packet(self.username, "p2p_broadcast", message)
                        self.socket.sendto(packet, (peer_info.host, peer_info.port))
                        
                        # Gönderim sayacını artır
                        with self.peers_lock:
                            if peer in self.peers:
                                self.peers[peer].packet_sent += 1
                        
                        sent_count += 1
                        print(f"[+] Mesaj gönderildi: {peer}")
                    else:
                        print(f"[!] Geçersiz peer bilgisi: {peer}")
                        
                except Exception as e:
                    print(f"[!] Broadcast hatası ({peer}): {e}")
        
        if sent_count == 0:
            print("[!] Hiçbir peer'a mesaj gönderilemedi")
        else:
            print(f"[+] Mesaj {sent_count} peer'a başarıyla gönderildi")
            
        return sent_count
                        
    def measure_rtt(self, peer_username: str) -> Optional[float]:
        """Belirli bir eş düğümle RTT ölçümü yap"""
        with self.peers_lock:
            if peer_username not in self.peers:
                return None
                
            peer_info = self.peers[peer_username]
            try:
                # Ping gönder
                ping_time = time.time()
                ping_packet = build_packet(
                    self.username, "p2p_ping",
                    extra_payload={"ping_time": str(ping_time)}
                )
                self.socket.sendto(ping_packet, (peer_info.host, peer_info.port))
                
                # Pong yanıtını bekle
                self.socket.settimeout(5.0)
                data, _ = self.socket.recvfrom(MAX_PACKET_SIZE)
                pong_packet = parse_packet(data)
                
                if pong_packet and pong_packet["header"]["type"] == "p2p_pong":
                    if "extra" in pong_packet["payload"] and "ping_time" in pong_packet["payload"]["extra"]:
                        sent_time = float(pong_packet["payload"]["extra"]["ping_time"])
                        rtt = (time.time() - sent_time) * 1000  # ms cinsinden
                        
                        # RTT ölçümünü kaydet
                        if peer_username not in self.rtt_measurements:
                            self.rtt_measurements[peer_username] = []
                        self.rtt_measurements[peer_username].append(rtt)
                        if len(self.rtt_measurements[peer_username]) > 10:  # Son 10 ölçümü tut
                            self.rtt_measurements[peer_username].pop(0)
                            
                        return rtt
                        
            except:
                pass
            finally:
                self.socket.settimeout(None)
        return None
        
    def get_network_status(self) -> Dict:
        """Ağ durumu bilgilerini döndür"""
        status = {
            "node": f"{self.username}@{self.host}:{self.port}",
            "peers": {},
            "rtt_stats": {},
            "connections": {},
            "active_peers": 0,
            "total_sent": 0,
            "total_received": 0
        }
        
        with self.peers_lock:
            active_count = 0
            total_sent = 0
            total_received = 0
            
            for peer, peer_info in self.peers.items():
                time_since_last_seen = time.time() - peer_info.last_seen
                is_active = time_since_last_seen < 60  # Son 60 saniyede görüldü mü
                
                if is_active:
                    active_count += 1
                
                total_sent += peer_info.packet_sent
                total_received += peer_info.packet_received
                
                status["peers"][peer] = {
                    "address": f"{peer_info.host}:{peer_info.port}",
                    "last_seen": time_since_last_seen,
                    "is_active": is_active,
                    "packets_sent": peer_info.packet_sent,
                    "packets_received": peer_info.packet_received
                }
            
            status["active_peers"] = active_count
            status["total_sent"] = total_sent
            status["total_received"] = total_received
            
            for peer, peer_info in self.peers.items():
                status["connections"][peer] = time.time() - peer_info.last_seen
                
                if peer in self.rtt_measurements and self.rtt_measurements[peer]:
                    rtts = self.rtt_measurements[peer]
                    status["rtt_stats"][peer] = {
                        "current": rtts[-1],
                        "avg": sum(rtts) / len(rtts),
                        "min": min(rtts),
                        "max": max(rtts)
                    }
                    
        return status
        
    def _receive_loop(self):
        """Gelen mesajları işle"""
        while self.is_running:
            try:
                data, addr = self.socket.recvfrom(MAX_PACKET_SIZE)
                packet = parse_packet(data)
                if not packet:
                    continue
                    
                self._handle_packet(packet, addr)
                
            except Exception as e:
                if self.is_running:  # Sadece beklenmeyen hataları göster
                    print(f"[!] P2P alıcı hatası: {e}")
                    
    def _handle_packet(self, packet: Dict, addr: Tuple[str, int]):
        """Gelen paketi işle"""
        header = packet["header"]
        msg_type = header["type"]
        sender = header["sender"]
        
        # Son görülme zamanını güncelle
        with self.peers_lock:
            for peer_info in self.peers.values():
                # Host adreslerini normalize ederek karşılaştır
                normalized_peer_host = "127.0.0.1" if peer_info.host == "localhost" else peer_info.host
                normalized_addr_host = "127.0.0.1" if addr[0] == "localhost" else addr[0]
                if normalized_peer_host == normalized_addr_host and peer_info.port == addr[1]:
                    peer_info.last_seen = time.time()
                    peer_info.packet_received += 1
                    break
        
        if msg_type == "p2p_connect":
            # Bağlantı isteği
            if "extra" in packet["payload"]:
                extra = packet["payload"]["extra"]
                peer_host = extra.get("host")
                peer_port = extra.get("port")
                peer_username = extra.get("username")
                
                if peer_username and peer_host and peer_port:
                    # Zaten bağlı mı kontrol et
                    already_connected = False
                    with self.peers_lock:
                        for existing_peer in self.peers.values():
                            if (existing_peer.host == peer_host and 
                                existing_peer.port == peer_port):
                                already_connected = True
                                break
                    
                    if not already_connected:
                        # Bağlantıyı kabul et
                        with self.peers_lock:
                            self.peers[peer_username] = PeerInfo(
                                peer_id=f"{peer_host}:{peer_port}",
                                username=peer_username,
                                host=peer_host,
                                port=peer_port,
                                last_seen=time.time()
                            )
                            
                        with self.graph_lock:
                            self.network_graph.add_node(peer_username)
                            self.network_graph.add_edge(self.username, peer_username)
                        
                        print(f"[+] Yeni P2P bağlantısı kabul edildi: {peer_username}@{peer_host}:{peer_port}")
                        
                    # Kabul yanıtı gönder
                    accept_packet = build_packet(
                        self.username, "p2p_accept",
                        extra_payload={"username": self.username}
                    )
                    self.socket.sendto(accept_packet, addr)
                    
        elif msg_type == "p2p_accept":
            # Bağlantı kabul yanıtı
            if "extra" in packet["payload"]:
                peer_username = packet["payload"]["extra"].get("username")
                if peer_username:
                    # Peer'ı listeye ekle (eğer yoksa)
                    already_connected = False
                    with self.peers_lock:
                        for existing_peer in self.peers.values():
                            # Host adreslerini normalize ederek karşılaştır
                            normalized_peer_host = "127.0.0.1" if existing_peer.host == "localhost" else existing_peer.host
                            normalized_addr_host = "127.0.0.1" if addr[0] == "localhost" else addr[0]
                            if (normalized_peer_host == normalized_addr_host and existing_peer.port == addr[1]):
                                already_connected = True
                                break
                    
                    if not already_connected:
                        # Host adresini normalize et
                        normalized_host = "127.0.0.1" if addr[0] == "localhost" else addr[0]
                        with self.peers_lock:
                            self.peers[peer_username] = PeerInfo(
                                peer_id=f"{normalized_host}:{addr[1]}",
                                username=peer_username,
                                host=normalized_host,
                                port=addr[1],
                                last_seen=time.time()
                            )
                            
                        with self.graph_lock:
                            self.network_graph.add_node(peer_username)
                            self.network_graph.add_edge(self.username, peer_username)
                        
                        print(f"[+] P2P bağlantısı kabul edildi: {peer_username}@{addr[0]}:{addr[1]}")
                    
        elif msg_type == "p2p_disconnect":
            # Bağlantı kesme
            if "extra" in packet["payload"]:
                peer_username = packet["payload"]["extra"].get("username")
                if peer_username:
                    self.disconnect_from_peer(peer_username)
                    
        elif msg_type == "p2p_ping":
            # Ping yanıtı
            if "extra" in packet["payload"] and "ping_time" in packet["payload"]["extra"]:
                ping_time = packet["payload"]["extra"]["ping_time"]
                pong_packet = build_packet(
                    self.username, "p2p_pong",
                    extra_payload={"ping_time": ping_time}
                )
                self.socket.sendto(pong_packet, addr)
                
        elif msg_type == "p2p_pong":
            # Pong yanıtı (RTT ölçümü için)
            pass  # RTT ölçümü zaten measure_rtt()'de yapılıyor
            
        elif msg_type == "p2p_message":
            # Doğrudan mesaj
            text = packet["payload"].get("text", "")
            print(f"\n>> {sender}: {text}")
            # Callback ile GUI'ye bildir (eğer varsa)
            if hasattr(self, 'message_callback') and self.message_callback:
                self.message_callback(f"{sender}: {text}")
            
        elif msg_type == "p2p_broadcast":
            # Yayın mesajı
            text = packet["payload"].get("text", "")
            print(f"\n>> [Yayın] {sender}: {text}")
            # Callback ile GUI'ye bildir (eğer varsa)
            if hasattr(self, 'message_callback') and self.message_callback:
                self.message_callback(f"{sender}: {text}")
                
            # ACK gönder
            try:
                ack_packet = build_packet(
                    self.username, "p2p_message_ack",
                    extra_payload={"received": True, "sender": sender}
                )
                self.socket.sendto(ack_packet, addr)
            except Exception as e:
                print(f"[!] ACK gönderme hatası: {e}")
                
        elif msg_type == "p2p_message_ack":
            # Mesaj ACK'i
            if "extra" in packet["payload"]:
                ack_sender = packet["payload"]["extra"].get("sender")
                print(f"[✓] Mesaj ACK alındı: {ack_sender} tarafından okundu")
            
    def _monitor_loop(self):
        """Ağ durumunu izle"""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Keep-alive ping gönder ve timeout kontrol et
                with self.peers_lock:
                    peers_to_remove = []
                    for peer, peer_info in self.peers.items():
                        # 120 saniye timeout (2 dakika)
                        if current_time - peer_info.last_seen > 120:
                            print(f"[!] {peer} bağlantısı zaman aşımına uğradı")
                            peers_to_remove.append(peer)
                        else:
                            # Keep-alive ping gönder (60 saniyede bir)
                            if current_time - peer_info.last_seen > 60:
                                try:
                                    keep_alive_packet = build_packet(
                                        self.username, "p2p_ping",
                                        extra_payload={"keep_alive": True}
                                    )
                                    self.socket.sendto(keep_alive_packet, (peer_info.host, peer_info.port))
                                except Exception as e:
                                    print(f"[!] Keep-alive gönderme hatası ({peer}): {e}")
                
                # Süresi dolan peer'ları kaldır
                for peer in peers_to_remove:
                    self.disconnect_from_peer(peer)
                    
            except Exception as e:
                print(f"[!] İzleme hatası: {e}")
                
            time.sleep(10)  # 10 saniyede bir kontrol et
            
    def _visualization_loop(self):
        """Ağ haritası görselleştirme döngüsü"""
        while self.is_visualization_running:
            try:
                # Kuyruktan güncelleme al
                if not self.visualization_queue.empty():
                    self._update_network_map()
                time.sleep(1)  # CPU kullanımını azalt
            except Exception as e:
                logging.error(f"Görselleştirme hatası: {e}")

    def _update_network_map(self):
        """Ağ haritasını güncelle"""
        try:
            if not self.network_window:
                self._create_network_window()
            
            # Ağ grafiğini güncelle
            self.network_ax.clear()
            pos = nx.spring_layout(self.network_graph)
            
            # Düğümleri çiz
            nx.draw_networkx_nodes(self.network_graph, pos,
                                 node_color='lightblue',
                                 node_size=1000,
                                 ax=self.network_ax)
            
            # Bağlantıları çiz
            nx.draw_networkx_edges(self.network_graph, pos,
                                 edge_color='gray',
                                 width=2,
                                 ax=self.network_ax)
            
            # Etiketleri çiz
            nx.draw_networkx_labels(self.network_graph, pos,
                                  font_size=10,
                                  font_family='sans-serif',
                                  ax=self.network_ax)
            
            # Başlık ve eksenleri güncelle
            self.network_ax.set_title("P2P Ağ Topolojisi")
            self.network_ax.axis('off')
            
            # Canvas'ı güncelle
            self.network_canvas.draw()
            
        except Exception as e:
            logging.error(f"Ağ haritası güncelleme hatası: {e}")

    def _create_network_window(self):
        """Ağ haritası penceresini oluştur"""
        try:
            # Tkinter penceresi oluştur
            self.network_window = tk.Toplevel()
            self.network_window.title("P2P Ağ Haritası")
            self.network_window.geometry("800x600")
            
            # Matplotlib figürü oluştur
            self.network_figure = plt.Figure(figsize=(10, 8), dpi=100)
            self.network_ax = self.network_figure.add_subplot(111)
            
            # Canvas oluştur
            self.network_canvas = FigureCanvasTkAgg(self.network_figure, master=self.network_window)
            self.network_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Pencere kapatıldığında
            def on_closing():
                self.is_visualization_running = False
                self.network_window.destroy()
                self.network_window = None
            
            self.network_window.protocol("WM_DELETE_WINDOW", on_closing)
            
        except Exception as e:
            logging.error(f"Ağ haritası penceresi oluşturma hatası: {e}")
            if self.network_window:
                self.network_window.destroy()
                self.network_window = None

    def show_network_map(self):
        """Ağ haritasını göster"""
        if not self.is_running:
            messagebox.showerror("Hata", "P2P düğümü çalışmıyor!")
            return
            
        try:
            # Görselleştirme kuyruğuna güncelleme ekle
            self.visualization_queue.put(True)
            
            if self.network_window:
                self.network_window.lift()  # Pencereyi öne getir
                self.network_window.focus_force()  # Odağı pencereye ver
                
        except Exception as e:
            logging.error(f"Ağ haritası gösterme hatası: {e}")
            messagebox.showerror("Hata", f"Ağ haritası gösterilemedi: {e}") 

    def _cleanup_loop(self):
        """Eski bağlantıları temizle"""
        while self.is_running:
            try:
                current_time = time.time()
                timeout = 120  # 120 saniye timeout (2 dakika)
                
                with self.peers_lock:
                    expired_peers = []
                    for peer, peer_info in self.peers.items():
                        if current_time - peer_info.last_seen > timeout:
                            expired_peers.append(peer)
                            peer_info.is_active = False
                    
                    # Süresi dolan peer'ları kaldır
                    for peer in expired_peers:
                        if peer in self.peers:
                            peer_info = self.peers[peer]
                            del self.peers[peer]
                            
                            # Grafikten kaldır
                            with self.graph_lock:
                                if self.network_graph.has_edge(self.username, peer):
                                    self.network_graph.remove_edge(self.username, peer)
                                
                                if self.network_graph.degree(peer) == 0 and peer != self.username:
                                    self.network_graph.remove_node(peer)
                            
                            print(f"[!] Timeout: {peer}")
                
                time.sleep(10)  # 10 saniyede bir kontrol et
                
            except Exception as e:
                print(f"[!] Temizlik hatası: {e}")

# Test kodu
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Kullanıcı adı: ")
    
    node = P2PNode(username=username)
    
    try:
        node.start()
        print(f"P2P düğümü çalışıyor. Çıkmak için Ctrl+C")
        
        while True:
            command = input("\nKomut (connect/disconnect/message/status/quit): ").strip().lower()
            
            if command == "quit":
                break
            elif command == "connect":
                host = input("Host: ")
                port = int(input("Port: "))
                peer_username = input("Peer username: ")
                if node.connect_to_peer(host, port, peer_username):
                    print("Bağlantı başarılı!")
                else:
                    print("Bağlantı başarısız!")
            elif command == "message":
                message = input("Mesaj: ")
                sent = node.broadcast_message(message)
                print(f"{sent} peer'a mesaj gönderildi")
            elif command == "status":
                status = node.get_network_status()
                print(f"Durum: {status}")
                
    except KeyboardInterrupt:
        print("\nÇıkılıyor...")
    finally:
        node.stop() 