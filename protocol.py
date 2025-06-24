"""
Simple Chat Protocol
Version: 1.0

This module defines the communication protocol for a simple chat application.
It includes specifications for packet structure, message types, and a basic
reliability layer for UDP communication.

Packet Format:
A packet is a JSON object with the following structure:
{
    "header": {
        "version": "1.0",
        "type": "message",      // See MESSAGE_TYPES for all types
        "sender": "username",
        "timestamp": "ISO-format-string",
        "seq": 123              // Optional sequence number for UDP
    },
    "payload": {
        "text": "message content",
        "extra": {}             // Optional dictionary for additional data
    }
}

Message Types:
- join: A user joins the chat.
- message: A standard public chat message.
- private_message: A private message sent over UDP.
- leave: A user leaves the chat.
- ack: An acknowledgment for a UDP packet.
- userlist: A list of connected users.
- ping/pong: Used for checking connectivity (TCP).
- peer_announce, peer_request, peer_list: For topology discovery.
- ping_topology, pong_topology: For RTT measurement in topology discovery.
- throughput_echo: For TCP throughput testing.

UDP Reliability:
To ensure reliable message delivery over UDP, the protocol uses:
- Sequence Numbers: To order packets and detect duplicates.
- Acknowledgments (ACKs): To confirm packet receipt.
- Timeouts and Retries: To resend lost packets.
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import struct
import socket

# Protocol constants
PROTOCOL_VERSION = "1.0"
MAX_PACKET_SIZE = 1024 * 1024  # 1MB, simple limit for packet size
RETRY_TIMEOUT = 5.0     # 5 seconds before resending a packet
MAX_RETRIES = 2         # Number of retries before giving up

# Supported message types
MESSAGE_TYPES = [
    "join", "message", "leave", "ack", "userlist",
    "ping", "pong", "peer_announce", "peer_request", "peer_list",
    "ping_topology", "pong_topology",
    "private_message",  # UDP private messaging support
    "throughput_echo" # For TCP throughput testing
]

def build_packet(sender: str, msg_type: str, text: str = "",
                 seq: Optional[int] = None, extra: Optional[Dict] = None) -> bytes:
    """
    Constructs a protocol-compliant packet.

    Args:
        sender (str): The username of the sender.
        msg_type (str): The type of the message (must be in MESSAGE_TYPES).
        text (str, optional): The main text content of the message. Defaults to "".
        seq (Optional[int], optional): A sequence number, typically for UDP. Defaults to None.
        extra (Optional[Dict], optional): A dictionary for additional data in the payload. Defaults to None.

    Raises:
        ValueError: If the message type is invalid or the resulting packet is too large.

    Returns:
        bytes: The JSON packet encoded in UTF-8.
    """
    if msg_type not in MESSAGE_TYPES:
        raise ValueError(f"Invalid message type: {msg_type}")

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

    # Ensure the packet does not exceed the maximum allowed size
    if len(data) > MAX_PACKET_SIZE:
        raise ValueError(f"Packet is too large: {len(data)} bytes")

    return data

def send_packet(sock: socket.socket, packet_bytes: bytes):
    """Prepends a 4-byte length header and sends the packet over the socket."""
    msg_len = len(packet_bytes)
    # '!' for network byte order, 'I' for unsigned int (4 bytes)
    header = struct.pack('!I', msg_len)
    sock.sendall(header + packet_bytes)

def receive_packet(sock: socket.socket) -> Optional[bytes]:
    """Reads a packet with a 4-byte length prefix from the socket."""
    # Read the header to determine the full message length
    header_data = sock.recv(4)
    if not header_data:
        return None  # Connection closed

    msg_len = struct.unpack('!I', header_data)[0]

    # Read the message data in chunks until the full message is received
    chunks = []
    bytes_received = 0
    while bytes_received < msg_len:
        # Request a chunk of up to 4096 bytes, or the remaining amount if smaller
        chunk = sock.recv(min(msg_len - bytes_received, 4096))
        if not chunk:
            raise ConnectionError("Socket connection broken while receiving data.")
        chunks.append(chunk)
        bytes_received += len(chunk)

    return b''.join(chunks)

def parse_packet(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses a byte string into a protocol packet (dictionary).

    Performs basic validation to ensure the packet has the required structure
    and a valid message type.

    Args:
        data (bytes): The raw byte data received from the socket.

    Returns:
        Optional[Dict[str, Any]]: The parsed packet as a dictionary, or None if parsing or validation fails.
    """
    try:
        packet = json.loads(data.decode('utf-8'))

        # Basic validation of the packet structure
        if not isinstance(packet, dict):
            return None
        if "header" not in packet or "payload" not in packet:
            return None
        if "type" not in packet["header"] or "sender" not in packet["header"]:
            return None
        if packet["header"]["type"] not in MESSAGE_TYPES:
            return None

        return packet
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Gracefully handle malformed packet data
        return None

# Basit UDP güvenilirlik için sequence tracking
class SimpleSequencer:
    """
    A simple class to manage sequence numbers for UDP communication.

    This helps in ordering packets and detecting duplicates. It is not
    thread-safe by itself and should be used with a lock in a multi-threaded
    environment.
    """
    def __init__(self):
        """Initializes the sequencer."""
        self.next_seq = 0
        self.received_seqs = set()  # Stores sequence numbers of received packets

    def get_next_seq(self) -> int:
        """
        Gets the next available sequence number and increments the counter.

        Returns:
            int: The next sequence number.
        """
        seq = self.next_seq
        self.next_seq += 1
        return seq

    def is_duplicate(self, seq: int) -> bool:
        """
        Checks if a sequence number has been seen before.

        If the sequence number is new, it is added to the set of received
        sequence numbers.

        Args:
            seq (int): The sequence number to check.

        Returns:
            bool: True if the sequence number is a duplicate, False otherwise.
        """
        if seq in self.received_seqs:
            return True
        self.received_seqs.add(seq)
        return False

    def mark_received(self, seq: int):
        """
        Explicitly marks a sequence number as received.

        Args:
            seq (int): The sequence number to mark.
        """
        self.received_seqs.add(seq)

# Global sequencer
sequencer = SimpleSequencer() 