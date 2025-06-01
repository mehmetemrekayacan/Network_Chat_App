"""
Chat Uygulaması Protokol Spesifikasyonu
Versiyon: 1.1

Bu modül, chat uygulamasının ağ protokolünü tanımlar ve yönetir.

- Paket yapısı, desteklenen mesaj tipleri, güvenilirlik ve parçalama mekanizmaları detaylı açıklanmıştır.
- Tüm fonksiyon ve sınıflar için kapsamlı docstring eklenmiştir.

Kullanım:
- build_packet: Protokole uygun yeni bir paket oluşturur.
- parse_packet: Gelen veriyi doğrular ve ayrıştırır.
- PacketFragmenter: Büyük paketleri parçalara böler ve birleştirir.
- SlidingWindow: Akış kontrolü ve güvenilirlik için pencere yönetimi sağlar.

Protokol Yapısı:
{
    "header": {
        "version": str,        # Protokol versiyonu (örn: "1.1")
        "type": str,          # Mesaj tipi
        "timestamp": str,     # ISO formatında zaman damgası
        "sender": str,        # Gönderen kullanıcı adı
        "seq": int,          # Sıra numarası
        "ack": int,          # Onay numarası
        "window": int,       # Pencere boyutu
        "fragment": {        # Paket parçalama bilgisi (opsiyonel)
            "id": int,       # Parça ID
            "total": int,    # Toplam parça sayısı
            "size": int      # Parça boyutu
        },
        "checksum": str      # SHA-256 hash
    },
    "payload": {
        "text": str,         # Mesaj metni
        "extra": dict        # Ek veri (opsiyonel)
    }
}

Mesaj Tipleri:
- join: Kullanıcı katılma
- message: Normal mesaj
- leave: Kullanıcı ayrılma
- ack: Onay mesajı
- error: Hata mesajı
- userlist: Kullanıcı listesi
- window_update: Pencere boyutu güncelleme
- ping: RTT ölçümü için istemciden sunucuya (veya P2P)
- pong: RTT ölçümü için sunucudan istemciye (veya P2P)
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import math

# Protokol sabitleri
PROTOCOL_VERSION = "1.1"
MAX_PACKET_SIZE = 4096  # bytes
MIN_PACKET_SIZE = 1024  # bytes (parçalama için minimum boyut)
MAX_WINDOW_SIZE = 10    # Maksimum pencere boyutu
INITIAL_WINDOW_SIZE = 5 # Başlangıç pencere boyutu
MAX_RETRIES = 5        # Maksimum yeniden gönderim denemesi
RETRY_TIMEOUT = 2.0    # Yeniden gönderim zaman aşımı (saniye)
FRAGMENT_TIMEOUT = 5.0 # Parça zaman aşımı (saniye)

SUPPORTED_MESSAGE_TYPES = {
    "join", "message", "leave", "ack", "error", 
    "userlist", "window_update", "ping", "pong"
}

class PacketFragmenter:
    """Paket parçalama ve birleştirme işlemlerini yönetir"""
    
    def __init__(self):
        self.fragments: Dict[int, Dict[int, bytes]] = {}  # {fragment_id: {fragment_no: data}}
        self.fragment_times: Dict[int, float] = {}  # {fragment_id: timestamp}
    
    def fragment_packet(self, data: bytes, max_size: int = MIN_PACKET_SIZE) -> List[bytes]:
        """Büyük paketi parçalara böler"""
        if len(data) <= max_size:
            return [data]
            
        fragments = []
        fragment_id = int(datetime.now().timestamp() * 1000)  # Benzersiz ID
        total_fragments = math.ceil(len(data) / max_size)
        
        for i in range(total_fragments):
            start = i * max_size
            end = min(start + max_size, len(data))
            fragment_data = data[start:end]
            
            # Parça başlığı oluştur
            fragment_header = {
                "header": {
                    "version": PROTOCOL_VERSION,
                    "type": "message",
                    "timestamp": datetime.now().isoformat(),
                    "fragment": {
                        "id": fragment_id,
                        "total": total_fragments,
                        "size": len(fragment_data)
                    }
                }
            }
            
            # Parçayı JSON formatına dönüştür
            fragment_json = json.dumps(fragment_header).encode()
            fragment_size = len(fragment_json)
            
            # Parça verisi ve başlığını birleştir
            fragment = fragment_json + b"\n" + fragment_data
            fragments.append(fragment)
            
        return fragments
    
    def add_fragment(self, fragment_id: int, fragment_no: int, 
                    total_fragments: int, data: bytes) -> Optional[bytes]:
        """Parçayı ekler ve tüm parçalar tamamlandığında birleştirir"""
        current_time = datetime.now().timestamp()
        
        # Eski parçaları temizle
        for fid in list(self.fragment_times.keys()):
            if current_time - self.fragment_times[fid] > FRAGMENT_TIMEOUT:
                del self.fragments[fid]
                del self.fragment_times[fid]
        
        # Yeni parça ekle
        if fragment_id not in self.fragments:
            self.fragments[fragment_id] = {}
            self.fragment_times[fragment_id] = current_time
            
        self.fragments[fragment_id][fragment_no] = data
        
        # Tüm parçalar tamamlandı mı kontrol et
        if len(self.fragments[fragment_id]) == total_fragments:
            # Parçaları sırala ve birleştir
            complete_data = b""
            for i in range(total_fragments):
                complete_data += self.fragments[fragment_id][i]
            
            # Parçaları temizle
            del self.fragments[fragment_id]
            del self.fragment_times[fragment_id]
            
            return complete_data
            
        return None

class SlidingWindow:
    """Pencere boyutu kontrolü ve sıralama yönetimi"""
    
    def __init__(self, initial_window_size: int = INITIAL_WINDOW_SIZE):
        self.window_size = initial_window_size
        self.base = 0  # Pencere başlangıcı
        self.next_seq = 0  # Sonraki sıra numarası
        self.packets: Dict[int, Tuple[bytes, float]] = {}  # {seq: (packet, timestamp)}
        self.acks: Dict[int, bool] = {}  # {seq: acked}
    
    def can_send(self) -> bool:
        """Yeni paket gönderilebilir mi kontrol et"""
        return self.next_seq < self.base + self.window_size
    
    def add_packet(self, packet: bytes) -> int:
        """Yeni paket ekle ve sıra numarası ata"""
        if not self.can_send():
            raise ValueError("Pencere dolu")
            
        seq = self.next_seq
        self.packets[seq] = (packet, datetime.now().timestamp())
        self.acks[seq] = False
        self.next_seq += 1
        return seq
    
    def mark_acked(self, seq: int):
        """Paketi onaylandı olarak işaretle"""
        if seq in self.acks:
            self.acks[seq] = True
            # Pencereyi kaydır
            while self.base in self.acks and self.acks[self.base]:
                del self.packets[self.base]
                del self.acks[self.base]
                self.base += 1
    
    def get_unacked_packets(self) -> List[Tuple[int, bytes]]:
        """Onaylanmamış paketleri döndür"""
        current_time = datetime.now().timestamp()
        unacked = []
        
        for seq, (packet, timestamp) in self.packets.items():
            if not self.acks[seq]:
                # Zaman aşımı kontrolü
                if current_time - timestamp > RETRY_TIMEOUT:
                    unacked.append((seq, packet))
                    self.packets[seq] = (packet, current_time)  # Zaman damgasını güncelle
                    
        return unacked
    
    def update_window_size(self, new_size: int):
        """Pencere boyutunu güncelle"""
        self.window_size = min(max(1, new_size), MAX_WINDOW_SIZE)

def calculate_checksum(data: Dict[str, Any]) -> str:
    """Verilen veri sözlüğünün SHA-256 hash'ini hesaplar"""
    # Header'dan checksum'ı çıkar
    header = data["header"].copy()
    header.pop("checksum", None)
    
    # Sıralı JSON string oluştur
    data_str = json.dumps({
        "header": header,
        "payload": data["payload"]
    }, sort_keys=True)
    
    # SHA-256 hash hesapla
    return hashlib.sha256(data_str.encode()).hexdigest()

def validate_packet(packet: Dict[str, Any]) -> bool:
    """Paketin geçerliliğini kontrol eder"""
    try:
        # Gerekli alanların kontrolü
        if not all(k in packet for k in ["header", "payload"]):
            return False
        if not all(k in packet["header"] for k in ["version", "type", "timestamp", "sender"]):
            return False
            
        # Protokol versiyonu kontrolü
        if packet["header"]["version"] != PROTOCOL_VERSION:
            return False
            
        # Mesaj tipi kontrolü
        if packet["header"]["type"] not in SUPPORTED_MESSAGE_TYPES:
            return False
            
        # Checksum kontrolü
        stored_checksum = packet["header"].get("checksum")
        if not stored_checksum:
            return False
            
        calculated_checksum = calculate_checksum(packet)
        if stored_checksum != calculated_checksum:
            return False
            
        # Paket boyutu kontrolü
        packet_size = len(json.dumps(packet).encode())
        if packet_size > MAX_PACKET_SIZE:
            return False
            
        return True
    except:
        return False

def build_packet(
    sender: str,
    msg_type: str,
    text: str = "",
    seq: Optional[int] = None,
    ack: Optional[int] = None,
    window: Optional[int] = None,
    fragment_info: Optional[Dict[str, int]] = None,
    extra_payload: Optional[Dict[str, Any]] = None
) -> bytes:
    """Yeni bir paket oluşturur ve döndürür"""
    if msg_type not in SUPPORTED_MESSAGE_TYPES:
        raise ValueError(f"Desteklenmeyen mesaj tipi: {msg_type}")
        
    # Paket yapısını oluştur
    packet = {
        "header": {
            "version": PROTOCOL_VERSION,
            "type": msg_type,
            "timestamp": datetime.now().isoformat(),
            "sender": sender
        },
        "payload": {
            "text": text
        }
    }
    
    # Opsiyonel alanları ekle
    if seq is not None:
        packet["header"]["seq"] = seq
    if ack is not None:
        packet["header"]["ack"] = ack
    if window is not None:
        packet["header"]["window"] = window
    if fragment_info:
        packet["header"]["fragment"] = fragment_info
    if extra_payload:
        packet["payload"]["extra"] = extra_payload
        
    # Checksum hesapla ve ekle
    packet["header"]["checksum"] = calculate_checksum(packet)
    
    # Paket boyutunu kontrol et
    encoded_packet = json.dumps(packet).encode()
    if len(encoded_packet) > MAX_PACKET_SIZE:
        raise ValueError(f"Paket boyutu çok büyük: {len(encoded_packet)} bytes")
        
    return encoded_packet

def parse_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Gelen veriyi pakete dönüştürür ve doğrular"""
    try:
        # Parça başlığı kontrolü
        if b"\n" in data:
            header_data, payload_data = data.split(b"\n", 1)
            header = json.loads(header_data.decode())
            if "fragment" in header["header"]:
                # Parça verisi, orijinal formatta döndür
                return {
                    "header": header["header"],
                    "payload": {"data": payload_data}
                }
        
        # Normal paket
        packet = json.loads(data.decode())
        if validate_packet(packet):
            return packet
    except:
        pass
    return None

# Global nesneler
fragmenter = PacketFragmenter()
window = SlidingWindow() 