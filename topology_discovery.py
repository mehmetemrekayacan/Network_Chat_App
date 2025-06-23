"""
Network Topology Discovery Service

This module implements a peer-to-peer network discovery service using UDP.
It is responsible for finding other nodes (peers) on the local network,
maintaining a list of them, and measuring the Round-Trip Time (RTT).

How it works:
- A peer broadcasts "announcement" messages to a well-known port.
- Other peers listen on this port, add new peers to their list, and reply
  with their own peer list.
- Periodically, each peer pings the others to calculate RTT and checks for
  stale peers to remove them.
"""
import socket
import threading
import time
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from protocol import build_packet, parse_packet

class NetworkTopologyDiscovery:
    """Manages the discovery of peers, RTT measurement, and peer list maintenance."""

    def __init__(self):
        """Initializes the NetworkTopologyDiscovery service."""
        # {peer_id: {"ip": str, "port": int, "rtt": float, "last_seen": time, ...}}
        self.peers: Dict[str, Dict] = {}
        self.discovery_port = 12347  # Port dedicated to discovery traffic
        self.lock = threading.Lock() # Lock for thread-safe access to self.peers
        self.is_running = False      # Flag to control background threads
        self.sock: Optional[socket.socket] = None
        self.peer_id: str = "uninitialized"

    def get_local_ips(self) -> list:
        """
        Attempts to find all local IP addresses for the machine.

        Returns:
            list: A list of local IP addresses as strings.
        """
        import socket
        local_ips = ["127.0.0.1", "localhost"]
        try:
            # Get IP from hostname
            hostname = socket.gethostname()
            host_ip = socket.gethostbyname(hostname)
            local_ips.append(host_ip)

            # Trick to get the primary network interface IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                local_ips.append(local_ip)
        except Exception:
            pass # Can fail in some network configs
        return list(set(local_ips))

    def start_discovery(self, peer_id: str):
        """
        Starts the topology discovery service.

        Binds the discovery socket and starts all background threads for listening,
        announcing, and RTT measurement.

        Args:
            peer_id (str): The unique identifier for this local peer.
        """
        self.peer_id = peer_id
        if self.is_running:
            return
        self.is_running = True

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Allow reusing the address to prevent "Address already in use" errors
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Enable broadcasting for this socket
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Bind to the discovery port
            try:
                self.sock.bind(("0.0.0.0", self.discovery_port))
                print(f"[*] Discovery socket bound to: 0.0.0.0:{self.discovery_port}")
            except OSError as e:
                # Fallback if the default port is in use
                print(f"[!] Port {self.discovery_port} is unavailable: {e}. Trying other ports.")
                for port in range(self.discovery_port + 1, self.discovery_port + 10):
                    try:
                        self.sock.bind(("0.0.0.0", port))
                        self.discovery_port = port
                        print(f"[*] Discovery socket bound to alternative port: {port}")
                        break
                    except OSError:
                        continue
                else: # If no port in the range is free, use a random one
                    self.sock.bind(("0.0.0.0", 0))
                    self.discovery_port = self.sock.getsockname()[1]
                    print(f"[*] Discovery socket bound to random port: {self.discovery_port}")

            # Start background threads
            threading.Thread(target=self.listen_discovery, daemon=True).start()
            threading.Thread(target=self.periodic_discovery, daemon=True).start()
            threading.Thread(target=self.rtt_measurement, daemon=True).start()

            print(f"[*] Network topology discovery started for peer '{peer_id}' on port {self.discovery_port}")

            # Send an initial announcement to be discovered quickly
            time.sleep(1)
            self.broadcast_announcement()

        except Exception as e:
            print(f"[!] Failed to start topology discovery: {e}")
            self.is_running = False

    def stop_discovery(self):
        """Stops the discovery service and cleans up resources."""
        if not self.is_running:
            return
        self.is_running = False
        print("[*] Stopping network topology discovery...")
        
        with self.lock:
            peer_count = len(self.peers)
            if peer_count > 0:
                print(f"[Cleanup] Clearing {peer_count} peers on shutdown.")
                self.peers.clear()

        if self.sock:
            self.sock.close()
            self.sock = None
        print("[*] Network topology discovery stopped.")

    def listen_discovery(self):
        """Listens for discovery messages in a loop. Runs in a dedicated thread."""
        print(f"[*] Discovery listener started for peer: {self.peer_id}")

        while self.is_running and self.sock:
            try:
                self.sock.settimeout(2.0)
                data, addr = self.sock.recvfrom(2048)

                # A quick pre-check and log for important packet types
                try:
                    quick_check = json.loads(data.decode('utf-8'))
                    msg_type = quick_check.get("type", "unknown")
                    peer_id = quick_check.get("peer_id", "unknown")

                    if msg_type in ["ping_topology", "pong_topology"]:
                        timestamp = quick_check.get("timestamp", 0)
                        print(f"[{msg_type.upper()}] from {peer_id} @ {addr} (ts: {timestamp:.3f})")

                except Exception:
                    print(f"[RX] Received invalid packet from {addr}")
                    continue

                self.handle_discovery_packet(data, addr)

            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"[!] Discovery listen loop error: {e}")
                    time.sleep(1)

    def handle_discovery_packet(self, data: bytes, addr: Tuple[str, int]):
        """
        Parses and dispatches a received discovery packet to the correct handler.

        Args:
            data (bytes): The raw packet data received from the socket.
            addr (Tuple[str, int]): The address (ip, port) of the sender.
        """
        try:
            # We use json.loads directly as discovery packets are not standard protocol packets
            packet = json.loads(data.decode('utf-8'))
            msg_type = packet.get("type")
            peer_id = packet.get("peer_id")

            # Ignore packets from self
            if peer_id == self.peer_id:
                return

            # Route to the appropriate handler
            if msg_type == "peer_announce":
                self.handle_peer_announce(peer_id, addr, packet)
            elif msg_type == "ping_topology":
                self.handle_ping_topology(peer_id, addr, packet)
            elif msg_type == "pong_topology":
                self.handle_pong_topology(peer_id, addr, packet)

        except (json.JSONDecodeError, UnicodeDecodeError):
            pass # Ignore malformed packets
        except Exception as e:
            print(f"[!] Error processing discovery packet: {e}")

    def handle_peer_announce(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """
        Processes a peer announcement. Adds or updates the peer in the list.

        Args:
            peer_id (str): The unique ID of the announcing peer.
            addr (Tuple[str, int]): The address of the peer.
            packet (dict): The announcement packet.
        """
        print(f"[Announce] Received from {peer_id} at {addr}")

        with self.lock:
            # Add new peer or update existing one
            self.peers[peer_id] = {
                "ip": addr[0],
                "port": addr[1],
                "discovery_port": addr[1], # The port they announced from
                "rtt": self.peers.get(peer_id, {}).get("rtt", 0.0), # Preserve old RTT if available
                "last_seen": time.time()
            }
            print(f"[+] Discovered peer: {peer_id}")

        # Respond with a direct announcement to ensure two-way discovery
        self.send_direct_response_announcement(addr)

    def send_direct_response_announcement(self, addr: Tuple[str, int]):
        """
        Sends a direct 'peer_announce' packet back to a specific address.

        Args:
            addr (Tuple[str, int]): The destination address for the announcement.
        """
        if not hasattr(self, 'peer_id'): return

        response_packet = {
            "type": "peer_announce",
            "peer_id": self.peer_id,
            "timestamp": time.time()
        }
        
        try:
            if self.sock:
                self.sock.sendto(json.dumps(response_packet).encode('utf-8'), addr)
                print(f"[Announce] Sent direct response to {addr}")
        except Exception as e:
            print(f"[!] Failed to send direct announcement to {addr}: {e}")

    def handle_ping_topology(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """
        Handles a topology ping by replying with a pong.

        Args:
            peer_id (str): The ID of the pinging peer.
            addr (Tuple[str, int]): The address of the pinging peer.
            packet (dict): The received ping packet.
        """
        pong_packet = {
            "type": "pong_topology",
            "peer_id": self.peer_id,
            "timestamp": packet.get("timestamp", 0), # Echo the original timestamp
            "ping_id": packet.get("ping_id")
        }

        try:
            if self.sock:
                self.sock.sendto(json.dumps(pong_packet).encode('utf-8'), addr)
        except Exception as e:
            print(f"[!] Failed to send pong to {peer_id}: {e}")

    def handle_pong_topology(self, peer_id: str, addr: Tuple[str, int], packet: dict):
        """
        Handles a pong packet and calculates the Round-Trip Time (RTT).

        Args:
            peer_id (str): The ID of the peer that sent the pong.
            addr (Tuple[str, int]): The address of the pong sender.
            packet (dict): The received pong packet.
        """
        send_time = packet.get("timestamp", 0)
        ping_id = packet.get("ping_id")
        
        if not send_time or not ping_id: return
        
        # Verify this pong is in response to a ping we sent
        if not ping_id.startswith(f"{self.peer_id}_"):
            return

        # Calculate RTT in milliseconds
        rtt = (time.time() - send_time) * 1000

        print(f"[RTT] Received pong from {peer_id}, RTT: {rtt:.2f} ms")

        with self.lock:
            if peer_id in self.peers:
                self.peers[peer_id]["rtt"] = rtt
                self.peers[peer_id]["last_seen"] = time.time()
            else:
                # This can happen if we receive a pong from a peer not yet in our list
                print(f"[!] Received pong from unknown peer {peer_id}, adding them.")
                self.peers[peer_id] = {
                    "ip": addr[0],
                    "port": addr[1],
                    "discovery_port": addr[1],
                    "rtt": rtt,
                    "last_seen": time.time()
                }

    def periodic_discovery(self):
        """Periodically broadcasts announcements and cleans up old peers."""
        announcement_interval = 15 # seconds
        while self.is_running:
            try:
                self.broadcast_announcement()
                self.cleanup_old_peers()
                time.sleep(announcement_interval)
            except Exception as e:
                print(f"[!] Periodic discovery thread error: {e}")

    def broadcast_announcement(self):
        """Announces this peer's presence to the network via UDP broadcast."""
        if not (hasattr(self, 'peer_id') and self.sock):
            return

        packet = {
            "type": "peer_announce",
            "peer_id": self.peer_id,
            "timestamp": time.time()
        }
        packet_bytes = json.dumps(packet).encode('utf-8')

        try:
            # Send to the broadcast address for network-wide discovery
            self.sock.sendto(packet_bytes, ('<broadcast>', self.discovery_port))
            # Also send to localhost for local testing
            self.sock.sendto(packet_bytes, ('127.0.0.1', self.discovery_port))
        except Exception as e:
            print(f"[!] Broadcast announcement failed: {e}")

    def rtt_measurement(self):
        """Periodically pings all known peers to measure RTT."""
        ping_interval = 10 # seconds
        print(f"[*] RTT measurement thread started (interval: {ping_interval}s)")
        time.sleep(3) # Initial delay

        while self.is_running:
            try:
                with self.lock:
                    # Create a copy to avoid locking during network I/O
                    peers_to_ping = list(self.peers.items())

                for peer_id, info in peers_to_ping:
                    # Only ping peers seen recently
                    if time.time() - info.get("last_seen", 0) < 60:
                        addr = (info["ip"], info.get("discovery_port", self.discovery_port))
                        self.ping_peer(peer_id, addr)

                time.sleep(ping_interval)

            except Exception as e:
                print(f"[!] RTT measurement thread error: {e}")

    def ping_peer(self, peer_id: str, addr: Tuple[str, int]):
        """
        Sends a single ping packet to a specific peer.

        Args:
            peer_id (str): The ID of the peer to ping.
            addr (Tuple[str, int]): The address of the peer to ping.
        """
        if not (hasattr(self, 'peer_id') and self.sock): return
        if peer_id == self.peer_id: return # Don't ping self

        timestamp = time.time()
        packet = {
            "type": "ping_topology",
            "peer_id": self.peer_id,
            "timestamp": timestamp,
            "ping_id": f"{self.peer_id}_{timestamp:.3f}" # Unique ID for this ping
        }

        try:
            self.sock.sendto(json.dumps(packet).encode('utf-8'), addr)
        except Exception as e:
            print(f"[!] Ping to {peer_id} at {addr} failed: {e}")

    def cleanup_old_peers(self):
        """Removes peers that have not been seen for longer than the timeout."""
        current_time = time.time()
        timeout = 45  # seconds

        with self.lock:
            expired_peers = [
                peer_id for peer_id, info in self.peers.items()
                if current_time - info.get("last_seen", 0) > timeout
            ]

            for peer_id in expired_peers:
                print(f"[-] Peer timed out, removing: {peer_id}")
                del self.peers[peer_id]

    def get_network_topology(self) -> Dict:
        """
        Returns a snapshot of the current network topology.

        Returns:
            Dict: A dictionary containing details about the local peer and all known peers.
        """
        with self.lock:
            return {
                "peers": dict(self.peers),
                "local_peer": getattr(self, 'peer_id', 'Not initialized'),
                "total_peers": len(self.peers),
                "discovery_time": datetime.now().isoformat()
            }

    def get_peer_list(self) -> List[Dict]:
        """
        Returns a formatted list of peers with their current status.

        Returns:
            List[Dict]: A list of dictionaries, each representing a peer.
        """
        with self.lock:
            status_timeout = 30 # seconds
            return [
                {
                    "peer_id": peer_id,
                    "ip": info["ip"],
                    "port": info.get("port", 0),
                    "rtt": info.get("rtt", 0.0),
                    "status": "active" if (time.time() - info.get("last_seen", 0)) < status_timeout else "inactive"
                }
                for peer_id, info in self.peers.items()
            ]

# Global instance of the discovery service for easy access from other modules
topology_discovery = NetworkTopologyDiscovery() 