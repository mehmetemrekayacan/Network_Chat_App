"""
Reliable UDP Chat Server

This module provides a UDP-based server for a chat application, focusing on
private messaging. It implements a simple reliability layer on top of the
connectionless UDP protocol to ensure message delivery.

Features:
- Reliable Messaging: Uses sequence numbers, acknowledgments (ACKs), and a
  timeout/retry mechanism to handle lost packets.
- Client Management: Tracks connected clients and their last seen times.
- Background Tasks: Uses separate threads for listening, retrying failed
  messages, and cleaning up inactive clients.
- Private Message Forwarding: Parses and forwards private messages to the
  intended recipients.
"""
import socket
import threading
import time
from typing import Union
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, RETRY_TIMEOUT, MAX_RETRIES,
    sequencer
)

class UDPServer:
    """
    A UDP server that handles private messaging with a custom reliability layer.
    """
    def __init__(self, host="0.0.0.0", port=12345):
        """
        Initializes the UDP server.

        Args:
            host (str, optional): The host address to bind to. Defaults to "0.0.0.0".
            port (int, optional): The port to listen on. Defaults to 12345.
        """
        self.host = host
        self.port = port
        self.sock = None
        self.is_running = False
        
        # Client management
        self.clients = {}  # Stores client info -> {addr: {"username": str, "last_seen": time}}
        self.lock = threading.Lock()  # Thread-safe access to self.clients
        
        # Reliability mechanism
        # Stores messages that are waiting for an ACK from the client.
        # {(addr, seq): {"packet": bytes, "timestamp": time, "retries": int}}
        self.pending_messages = {}
        
    def start(self):
        """
        Starts the UDP server and its background threads.

        Binds the UDP socket and starts threads for listening to incoming packets,
        retrying unacknowledged messages, and cleaning up timed-out clients.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            self.is_running = True
            
            print(f"[*] UDP Server started at {self.host}:{self.port}")
            print(f"[*] Protokol v{PROTOCOL_VERSION}")
            
            # Start background threads
            threading.Thread(target=self.listen_loop, daemon=True).start()
            threading.Thread(target=self.retry_loop, daemon=True).start()
            threading.Thread(target=self.cleanup_loop, daemon=True).start()
            
            # Keep the main thread alive while the server is running
            while self.is_running:
                time.sleep(1)
                
        except Exception as e:
            print(f"[!] UDP Server error on startup: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stops the UDP server gracefully."""
        print("[*] Stopping UDP Server...")
        self.is_running = False
        if self.sock:
            self.sock.close()
        print("[*] UDP Server stopped.")
    
    def listen_loop(self):
        """Continuously listens for incoming UDP packets."""
        while self.is_running:
            try:
                data, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                self.handle_packet(data, addr)
            except Exception as e:
                if self.is_running:
                    print(f"[!] Listening loop error: {e}")
    
    def handle_packet(self, data: bytes, addr: tuple):
        """
        Parses and processes an incoming packet.

        This method acts as a dispatcher, routing the packet to the appropriate
        handler based on its type (e.g., join, message, ack). It also handles
        sending ACKs for packets that have a sequence number.

        Args:
            data (bytes): The raw packet data received.
            addr (tuple): The address (ip, port) of the sender.
        """
        packet = parse_packet(data)
        if not packet:
            return  # Ignore invalid packets
            
        msg_type = packet["header"]["type"]
        sender = packet["header"]["sender"]
        text = packet["payload"]["text"]
        seq = packet["header"].get("seq")
        
        # An ACK packet is just for confirmation, no further processing needed here.
        if msg_type == "ack":
            self.handle_ack(addr, seq)
            return
        
        # If a packet has a sequence number, it means the client expects an acknowledgment.
        if seq is not None:
            ack_packet = build_packet("SERVER", "ack", seq=seq)
            self.sock.sendto(ack_packet, addr)
        
        # To prevent processing the same message multiple times (e.g., if our ACK was lost)
        if seq is not None and sequencer.is_duplicate(seq):
            return  # Duplicate packet, ignore
            
        # --- Dispatch to the correct handler based on message type ---
        if msg_type == "join":
            self.handle_join(addr, sender)
        elif msg_type == "message":
            # In this server, a "message" type is treated as a public broadcast
            self.broadcast_message(packet, addr)
        elif msg_type == "private_message":
            self.handle_private_message(packet, addr)
        elif msg_type == "leave":
            self.handle_leave(addr, sender)
        elif msg_type == "ping":
            self.handle_ping(addr, sender)
        
        # Update the client's last seen time to keep them from timing out.
        with self.lock:
            if addr in self.clients:
                self.clients[addr]["last_seen"] = time.time()
    
    def handle_join(self, addr: tuple, username: str):
        """
        Handles a user's request to join the UDP chat, allowing for reconnections.

        If a user with the same username joins from a new address, this method
        updates their entry to the new address, effectively handling a reconnect.

        Args:
            addr (tuple): The client's new address.
            username (str): The username chosen by the client.
        """
        with self.lock:
            # Check if this username is already registered, possibly from a different address
            old_address = None
            for client_address, client_info in self.clients.items():
                if client_info["username"] == username:
                    old_address = client_address
                    break

            # If the user is reconnecting from a new port/address, remove the old entry.
            if old_address and old_address != addr:
                print(f"[*] User '{username}' reconnected. Updating address from {old_address} to {addr}.")
                # This is a critical step: remove the stale entry before adding the new one.
                del self.clients[old_address]

            # Add the new client entry. This works for both new users and reconnections.
            self.clients[addr] = {
                "username": username,
                "last_seen": time.time()
            }
        
        # Announce the user's arrival to everyone else.
        join_msg_text = f"{username} has joined the chat."
        join_msg_packet = build_packet("SERVER", "message", join_msg_text)
        self.broadcast_to_all(join_msg_packet, exclude=[addr])
        
        # Send the current user list to the new client.
        self.send_user_list(addr)
        print(f"[+] UDP User Joined/Reconnected: {username} ({addr})")
    
    def handle_leave(self, addr: tuple, username: str):
        """
        Handles a user's departure from the chat.

        Args:
            addr (tuple): The client's address.
            username (str): The client's username.
        """
        with self.lock:
            if addr in self.clients:
                del self.clients[addr]
        
        # Announce the departure to everyone else
        leave_msg_text = f"{username} has left the chat."
        leave_msg_packet = build_packet("SERVER", "message", leave_msg_text)
        self.broadcast_to_all(leave_msg_packet, exclude=[addr])
        print(f"[-] UDP User Left: {username} ({addr})")
    
    def handle_ping(self, addr: tuple, sender: str):
        """
        Responds to a ping packet with a pong.

        Args:
            addr (tuple): The client's address.
            sender (str): The username of the client who sent the ping.
        """
        pong_packet = build_packet("SERVER", "pong", f"Pong to {sender}")
        self.reliable_send(pong_packet, addr)
    
    def handle_private_message(self, packet: dict, sender_addr: tuple):
        """
        Processes and forwards a private message.

        The message text is expected to be in the format "@target_user: message".
        It finds the target user's address and forwards the message.

        Args:
            packet (dict): The parsed private message packet.
            sender_addr (tuple): The address of the message sender.
        """
        sender = packet["header"]["sender"]
        text = packet["payload"]["text"]
        
        # Expected format: "@username: message"
        if text.startswith("@") and ":" in text:
            try:
                target_part, message_part = text.split(":", 1)
                target_user = target_part[1:].strip()  # Remove '@'
                message = message_part.strip()
                
                target_addr = None
                with self.lock:
                    # Find the address of the target user
                    for addr, client_info in self.clients.items():
                        if client_info["username"] == target_user:
                            target_addr = addr
                            break
                
                # The logic to check a TCP server's user list has been removed for clarity
                # as this server should operate independently.

                if target_addr:
                    # Forward the private message to the target user
                    private_packet = build_packet(sender, "private_message", f"[Private from {sender}] {message}")
                    self.reliable_send(private_packet, target_addr)
                    
                    # Send a confirmation back to the sender
                    confirm_msg = f"Your private message to {target_user} has been sent."
                    confirm_packet = build_packet("SERVER", "message", confirm_msg)
                    self.reliable_send(confirm_packet, sender_addr)
                    
                    print(f"[Private] {sender} -> {target_user}: {message}")
                else:
                    # Target user not found
                    error_msg = f"User '{target_user}' is not online or does not exist."
                    error_packet = build_packet("SERVER", "message", error_msg)
                    self.reliable_send(error_packet, sender_addr)
                    
            except Exception as e:
                error_packet = build_packet("SERVER", "message", f"Private message error: {e}")
                self.reliable_send(error_packet, sender_addr)
        else:
            # Inform the sender about the correct format
            format_error_msg = "Invalid private message format. Use: @username: message"
            error_packet = build_packet("SERVER", "message", format_error_msg)
            self.reliable_send(error_packet, sender_addr)
    
    def handle_ack(self, addr: tuple, seq: int):
        """
        Processes an acknowledgment packet.

        Removes the corresponding message from the pending list, so it won't be retried.

        Args:
            addr (tuple): The address of the client that sent the ACK.
            seq (int): The sequence number being acknowledged.
        """
        key = (addr, seq)
        if key in self.pending_messages:
            del self.pending_messages[key]
    
    def broadcast_message(self, packet: dict, sender_addr: tuple):
        """
        Broadcasts a public message to all clients except the sender.

        Args:
            packet (dict): The message packet to broadcast.
            sender_addr (tuple): The address of the message sender to exclude.
        """
        self.broadcast_to_all(packet, exclude=[sender_addr])
    
    def broadcast_to_all(self, packet_data: Union[dict, bytes], exclude: list = None):
        """
        Sends a packet to all connected clients.

        Args:
            packet_data (dict or bytes): The packet to send.
            exclude (list, optional): A list of addresses to exclude. Defaults to None.
        """
        if exclude is None:
            exclude = []
            
        with self.lock:
            # Iterate over a copy of keys to avoid issues if clients dict changes
            for addr in list(self.clients.keys()):
                if addr not in exclude:
                    self.reliable_send(packet_data, addr)
    
    def send_user_list(self, addr: tuple):
        """
        Sends the list of currently connected users to a specific client.

        Args:
            addr (tuple): The address of the client to send the list to.
        """
        with self.lock:
            users = [info["username"] for info in self.clients.values()]
        
        user_list_text = f"Connected users: {', '.join(users)}"
        user_list_packet = build_packet("SERVER", "userlist", user_list_text, extra={"users": users})
        self.reliable_send(user_list_packet, addr)
    
    def reliable_send(self, packet_data: Union[dict, bytes], addr: tuple):
        """
        Sends a packet reliably, expecting an ACK.

        This method adds a sequence number to the packet, sends it, and then
        stores it in a "pending" list to await acknowledgment.

        Args:
            packet_data (dict or bytes): The packet to be sent. If it's a dict,
                                         it will be built into a bytes object.
            addr (tuple): The destination address.
        """
        # If the packet is a dictionary, build it into bytes first.
        if isinstance(packet_data, dict):
            packet_data = build_packet(
                packet_data["header"]["sender"],
                packet_data["header"]["type"],
                packet_data["payload"]["text"],
                extra=packet_data["payload"].get("extra")
            )
        
        # Re-parse the packet to add a sequence number
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
        
        try:
            self.sock.sendto(final_packet, addr)
            # Add to the pending list for retry mechanism
            key = (addr, seq)
            self.pending_messages[key] = {
                "packet": final_packet,
                "timestamp": time.time(),
                "retries": 0
            }
        except Exception as e:
            print(f"[!] Send error to {addr}: {e}")
    
    def retry_loop(self):
        """
        A background thread that periodically checks for and resends unacknowledged messages.
        """
        while self.is_running:
            current_time = time.time()
            # Iterate over a copy of items as the dictionary may be modified
            for key, msg_info in list(self.pending_messages.items()):
                if (current_time - msg_info["timestamp"]) > RETRY_TIMEOUT:
                    if msg_info["retries"] < MAX_RETRIES:
                        # Resend the packet
                        addr, seq = key
                        try:
                            self.sock.sendto(msg_info["packet"], addr)
                            self.pending_messages[key]["timestamp"] = current_time
                            self.pending_messages[key]["retries"] += 1
                            print(f"[R] Retrying message to {addr} (seq={seq}, retry={msg_info['retries']})")
                        except Exception:
                            # The client might have disconnected, the cleanup loop will handle it.
                            pass
                    else:
                        # Max retries reached, give up on this message
                        del self.pending_messages[key]
                        print(f"[!] Message send failed after {MAX_RETRIES} retries: {key}")
            
            time.sleep(0.5)  # 500ms kontrol aralığı
    
    def cleanup_loop(self):
        """
        A background thread that periodically removes inactive clients.
        """
        while self.is_running:
            current_time = time.time()
            timeout = 180  # 3 minutes
            
            with self.lock:
                expired_clients = []
                for addr, client_info in self.clients.items():
                    if current_time - client_info["last_seen"] > timeout:
                        expired_clients.append(addr)
                
                for addr in expired_clients:
                    username = self.clients[addr]["username"]
                    del self.clients[addr]
                    print(f"[T] Timeout: {username} ({addr})")
            
            time.sleep(60)  # 1 dakikada bir kontrol

if __name__ == "__main__":
    server = UDPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Sunucu kapatılıyor...")
        server.stop()
