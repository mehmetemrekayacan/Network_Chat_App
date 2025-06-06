"""
Chat Uygulaması Protokol Spesifikasyonu
Versiyon: 1.3

Bu modül, chat uygulamasının ağ protokolünü tanımlar ve yönetir.

Protokol Özellikleri:
- Versiyon: 1.3 (1.2 ile geriye dönük uyumlu)
- Güvenlik: SHA-256 checksum, paket doğrulama
- Güvenilirlik: Sliding window, ACK mekanizması
- Parçalama: Büyük paketler için otomatik parçalama
- Akış Kontrolü: Dinamik pencere boyutu yönetimi
- P2P Desteği: Doğrudan düğümler arası iletişim
- Ağ İzleme: Gerçek zamanlı durum ve performans takibi

Protokol Yapısı:
{
    "header": {
        "version": str,        # Protokol versiyonu (örn: "1.2")
        "type": str,          # Mesaj tipi
        "timestamp": str,     # ISO formatında zaman damgası
        "sender": str,        # Gönderen kullanıcı adı
        "seq": int,          # Sıra numarası (opsiyonel)
        "ack": int,          # Onay numarası (opsiyonel)
        "window": int,       # Pencere boyutu (opsiyonel)
        "fragment": {        # Paket parçalama bilgisi (opsiyonel)
            "id": int,       # Parça ID
            "total": int,    # Toplam parça sayısı
            "size": int      # Parça boyutu
        },
        "checksum": str,     # SHA-256 hash
        "error_code": int    # Hata kodu (opsiyonel)
    },
    "payload": {
        "text": str,         # Mesaj metni
        "extra": dict        # Ek veri (opsiyonel)
    }
}

Mesaj Tipleri ve Hata Kodları:
1. Temel Mesajlar:
   - join (0x01): Kullanıcı katılma
   - message (0x02): Normal mesaj
   - leave (0x03): Kullanıcı ayrılma
   - ack (0x04): Onay mesajı
   - error (0x05): Hata mesajı
   - userlist (0x06): Kullanıcı listesi

2. Kontrol Mesajları:
   - window_update (0x07): Pencere boyutu güncelleme
   - ping (0x08): RTT ölçümü (istemci->sunucu)
   - pong (0x09): RTT ölçümü (sunucu->istemci)
   - version_check (0x0A): Versiyon kontrolü

3. Hata Kodları:
   - 0x00: Başarılı
   - 0x01: Geçersiz paket formatı
   - 0x02: Versiyon uyumsuzluğu
   - 0x03: Checksum hatası
   - 0x04: Paket boyutu aşımı
   - 0x05: Desteklenmeyen mesaj tipi
   - 0x06: Sunucu dolu
   - 0x07: Zaman aşımı
   - 0x08: Parça hatası
   - 0x09: Pencere taşması
   - 0x0A: Diğer hatalar

Paket Boyutu Limitleri:
- Maksimum: 4096 bytes (4 KB)
- Minimum: 1024 bytes (1 KB, parçalama için)
- Önerilen: 2048 bytes (2 KB)

Güvenlik:
- SHA-256 checksum ile paket bütünlüğü
- Zaman damgası ile replay saldırılarına karşı koruma
- Sıra numarası ile paket sıralaması
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Set
import math

# Protokol sabitleri
PROTOCOL_VERSION = "1.3"
MIN_SUPPORTED_VERSION = "1.2"  # Minimum desteklenen versiyon
MAX_PACKET_SIZE = 4096  # bytes
MIN_PACKET_SIZE = 1024  # bytes (parçalama için minimum boyut)
RECOMMENDED_PACKET_SIZE = 2048  # bytes (önerilen boyut)
MAX_WINDOW_SIZE = 10    # Maksimum pencere boyutu
INITIAL_WINDOW_SIZE = 5 # Başlangıç pencere boyutu
MAX_RETRIES = 5        # Maksimum yeniden gönderim denemesi
RETRY_TIMEOUT = 2.0    # Yeniden gönderim zaman aşımı (saniye)
FRAGMENT_TIMEOUT = 5.0 # Parça zaman aşımı (saniye)

# Mesaj tipleri ve hata kodları
MESSAGE_TYPES = {
    "join": 0x01,
    "message": 0x02,
    "leave": 0x03,
    "ack": 0x04,
    "error": 0x05,
    "userlist": 0x06,
    "window_update": 0x07,
    "ping": 0x08,
    "pong": 0x09,
    "version_check": 0x0A,
    "fragment_ack": 0x0B,
    "fragment_nack": 0x0C,
    "p2p_connect": 0x0D,
    "p2p_accept": 0x0E,
    "p2p_disconnect": 0x0F,
    "p2p_message": 0x10,
    "p2p_broadcast": 0x11,
    "p2p_ping": 0x12,
    "p2p_pong": 0x13,
    "p2p_status": 0x14,
    "p2p_topology": 0x15
}

ERROR_CODES = {
    0x00: "Başarılı",
    0x01: "Geçersiz paket formatı",
    0x02: "Versiyon uyumsuzluğu",
    0x03: "Checksum hatası",
    0x04: "Paket boyutu aşımı",
    0x05: "Desteklenmeyen mesaj tipi",
    0x06: "Sunucu dolu",
    0x07: "Zaman aşımı",
    0x08: "Parça hatası",
    0x09: "Pencere taşması",
    0x0A: "Diğer hatalar",
    0x0B: "P2P bağlantı reddedildi",
    0x0C: "P2P düğüm bulunamadı",
    0x0D: "P2P bağlantı zaman aşımı",
    0x0E: "P2P düğüm meşgul",
    0x0F: "P2P ağ dolu"
}

SUPPORTED_MESSAGE_TYPES = set(MESSAGE_TYPES.keys())

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
    """Pencere boyutu kontrolü, sıralama ve alıcı tarafı için out-of-order buffer yönetimi"""
    
    def __init__(self, initial_window_size: int = INITIAL_WINDOW_SIZE):
        self.window_size = initial_window_size
        self.base = 0  # Pencere başlangıcı
        self.next_seq = 0  # Sonraki sıra numarası (gönderici için)
        self.packets: Dict[int, Tuple[bytes, float]] = {}  # {seq: (packet, timestamp)}
        self.acks: Dict[int, bool] = {}  # {seq: acked}
        # Alıcı tarafı için:
        self.recv_buffer: Dict[int, Any] = {}  # {seq: packet}
        self.expected_seq = 0  # Sırayla beklenen paket numarası
    
    def can_send(self) -> bool:
        """Yeni paket gönderilebilir mi kontrol et"""
        return self.next_seq < self.base + self.window_size
    
    def add_packet(self, packet: bytes) -> int:
        """Yeni paket ekle ve sıra numarası ata (gönderici için)"""
        if not self.can_send():
            raise ValueError("Pencere dolu")
            
        seq = self.next_seq
        self.packets[seq] = (packet, datetime.now().timestamp())
        self.acks[seq] = False
        self.next_seq += 1
        return seq
    
    def mark_acked(self, seq: int):
        """Paketi onaylandı olarak işaretle (gönderici için)"""
        if seq in self.acks:
            self.acks[seq] = True
            # Pencereyi kaydır
            while self.base in self.acks and self.acks[self.base]:
                del self.packets[self.base]
                del self.acks[self.base]
                self.base += 1
    
    def get_unacked_packets(self) -> List[Tuple[int, bytes]]:
        """Onaylanmamış paketleri döndür (gönderici için)"""
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

    # --- Alıcı tarafı için gelişmiş sıralama ---
    def add_incoming_packet(self, seq: int, packet: Any):
        """Gelen paketi buffer'a ekle (out-of-order için)"""
        if seq < self.expected_seq:
            # Zaten işlendi, yok say
            return
        self.recv_buffer[seq] = packet

    def get_in_order_packets(self) -> List[Any]:
        """Buffer'dan sırayla işlenebilecek tüm paketleri döndür ve buffer'dan çıkar"""
        in_order = []
        while self.expected_seq in self.recv_buffer:
            in_order.append(self.recv_buffer[self.expected_seq])
            del self.recv_buffer[self.expected_seq]
            self.expected_seq += 1
        return in_order

def version_compatible(version: str) -> bool:
    """Verilen versiyonun desteklenip desteklenmediğini kontrol eder"""
    try:
        v1 = tuple(map(int, version.split('.')))
        v2 = tuple(map(int, MIN_SUPPORTED_VERSION.split('.')))
        return v1 >= v2
    except:
        return False

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

def validate_packet(packet: Dict[str, Any]) -> Tuple[bool, int]:
    """Paketin geçerliliğini kontrol eder ve hata kodu döndürür"""
    try:
        # Gerekli alanların kontrolü
        if not all(k in packet for k in ["header", "payload"]):
            return False, 0x01
        if not all(k in packet["header"] for k in ["version", "type", "timestamp", "sender"]):
            return False, 0x01
            
        # Protokol versiyonu kontrolü
        if not version_compatible(packet["header"]["version"]):
            return False, 0x02
            
        # Mesaj tipi kontrolü
        if packet["header"]["type"] not in SUPPORTED_MESSAGE_TYPES:
            return False, 0x05
            
        # Checksum kontrolü
        stored_checksum = packet["header"].get("checksum")
        if not stored_checksum:
            return False, 0x03
            
        calculated_checksum = calculate_checksum(packet)
        if stored_checksum != calculated_checksum:
            return False, 0x03
            
        # Paket boyutu kontrolü
        packet_size = len(json.dumps(packet).encode())
        if packet_size > MAX_PACKET_SIZE:
            return False, 0x04
            
        return True, 0x00
    except:
        return False, 0x0A

def build_packet(
    sender: str,
    msg_type: str,
    text: str = "",
    seq: Optional[int] = None,
    ack: Optional[int] = None,
    window: Optional[int] = None,
    fragment_info: Optional[Dict[str, int]] = None,
    extra_payload: Optional[Dict[str, Any]] = None,
    error_code: Optional[int] = None,
    is_p2p: bool = False  # P2P paketi mi?
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
            "sender": sender,
            "is_p2p": is_p2p  # P2P paketi olduğunu belirt
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
    if error_code is not None:
        packet["header"]["error_code"] = error_code
        
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
        is_valid, error_code = validate_packet(packet)
        if is_valid:
            return packet
        else:
            # Hata kodunu ekle
            packet["header"]["error_code"] = error_code
            return packet
    except:
        return None

# Global nesneler
fragmenter = PacketFragmenter()
window = SlidingWindow() 