"""
Basit Chat Protokolü
Versiyon: 1.0

Temel chat uygulaması için minimal protokol.
Gereksinimleri: multi-user chat, UDP reliability, topology discovery

Paket Formatı:
{
    "header": {
        "version": "1.0",
        "type": "message",
        "sender": "username", 
        "timestamp": "ISO-format",
        "seq": 123  # UDP için sequence number
    },
    "payload": {
        "text": "message content"
    }
}

Mesaj Tipleri:
- join: Kullanıcı katılma
- message: Normal mesaj  
- leave: Kullanıcı ayrılma
- ack: UDP onay mesajı
- userlist: Kullanıcı listesi
- ping/pong: RTT ölçümü
- topology_*: Network topology keşfi

UDP Güvenilirlik:
- Sequence number ile sıralama
- ACK ile onay
- Timeout ile yeniden gönderim
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

# Protokol sabitleri
PROTOCOL_VERSION = "1.0"
MAX_PACKET_SIZE = 1024  # 1KB (basit)
RETRY_TIMEOUT = 5.0     # 5 saniye
MAX_RETRIES = 2         # 2 deneme

# Mesaj tipleri
MESSAGE_TYPES = [
    "join", "message", "leave", "ack", "userlist", 
    "ping", "pong", "peer_announce", "peer_request", "peer_list",
    "ping_topology", "pong_topology",
    "private_message"  # UDP private messaging support
]

def build_packet(sender: str, msg_type: str, text: str = "", 
                seq: Optional[int] = None, extra: Optional[Dict] = None) -> bytes:
    """Basit paket oluştur"""
    if msg_type not in MESSAGE_TYPES:
        raise ValueError(f"Geçersiz mesaj tipi: {msg_type}")
        
    packet = {
        "header": {
            "version": PROTOCOL_VERSION,
            "type": msg_type,
            "sender": sender,
            "timestamp": datetime.now().isoformat()
        },
        "payload": {
            "text": text
        }
    }
    
    if seq is not None:
        packet["header"]["seq"] = seq
        
    if extra:
        packet["payload"]["extra"] = extra
    
    data = json.dumps(packet).encode('utf-8')
    
    if len(data) > MAX_PACKET_SIZE:
        raise ValueError(f"Paket çok büyük: {len(data)} bytes")
        
    return data

def parse_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """Basit paket parse et"""
    try:
        packet = json.loads(data.decode('utf-8'))
        
        # Temel validasyon
        if not isinstance(packet, dict):
            return None
        if "header" not in packet or "payload" not in packet:
            return None
        if "type" not in packet["header"] or "sender" not in packet["header"]:
            return None
        if packet["header"]["type"] not in MESSAGE_TYPES:
            return None
            
        return packet
    except:
        return None

# Basit UDP güvenilirlik için sequence tracking
class SimpleSequencer:
    def __init__(self):
        self.next_seq = 0
        self.received_seqs = set()
        
    def get_next_seq(self) -> int:
        seq = self.next_seq
        self.next_seq += 1
        return seq
        
    def is_duplicate(self, seq: int) -> bool:
        if seq in self.received_seqs:
            return True
        self.received_seqs.add(seq)
        return False
        
    def mark_received(self, seq: int):
        self.received_seqs.add(seq)

# Global sequencer
sequencer = SimpleSequencer() 