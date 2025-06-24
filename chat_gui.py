"""
Graphical User Interface for the Chat Application

This module provides the main GUI for the chat application, built with customtkinter.
It integrates the TCP (public chat), UDP (private chat), and topology
discovery services into a cohesive user interface.
"""
import customtkinter
import tkinter
from tkinter import messagebox
import threading
import time
import socket
import logging

# Import the backend modules
import server
import udp_server
import topology_discovery
from protocol import build_packet, receive_packet, send_packet

# Set the appearance and color theme for customtkinter
customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")

class SimpleChatApp:
    """
    The main class for the chat application GUI.

    It builds all UI components, manages application state (server/client mode),
    and handles user interactions and network events.
    """
    def __init__(self, master):
        """
        Initializes the SimpleChatApp.

        Args:
            master (customtkinter.CTk): The root customtkinter window.
        """
        self.master = master
        self.master.title("🎯 Network Chat Application - TCP/UDP & Topology Discovery")
        self.master.geometry("1000x700")

        # Connection state variables
        self.tcp_server = None
        self.udp_server = None
        self.tcp_server_thread = None
        self.udp_server_thread = None

        # Topology discovery module instance
        self.topology_discovery = topology_discovery.topology_discovery

        # Client mode state variables
        self.tcp_client_socket = None
        self.udp_client_socket = None
        self.is_client_mode = False

        # User and session data
        self.current_username = ""
        self.connected_users = []
        self.selected_user = None # For private messaging

        # UI components and config
        self.tcp_port = 12345
        self.udp_port = 12346
        self.server_port = self.tcp_port  # For backward compatibility

        # Performance test state
        self.rtt_tests = {}
        self.rtt_results = []
        self.throughput_start_time = 0
        self.throughput_packets_received = 0
        self.throughput_total_packets = 0

        self.setup_ui()

    def setup_ui(self):
        """Sets up the main user interface layout."""
        # This frame still fills the window, which is fine. The grid will be used inside it.
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=1)
        
        main_frame = customtkinter.CTkFrame(self.master, fg_color="transparent")
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Configure the grid to have one row and two columns
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=3)  # Chat area gets 3/4 of the space
        main_frame.grid_columnconfigure(1, weight=1)  # Control panel gets 1/4 of the space

        # UI is split into a left chat area and a right control panel
        self.setup_chat_area(main_frame)
        self.setup_control_panel(main_frame)

    def setup_chat_area(self, parent):
        """
        Sets up the left panel containing the chat display and message input.

        Args:
            parent (customtkinter.CTkFrame): The parent widget for this area.
        """
        chat_frame = customtkinter.CTkFrame(parent)
        chat_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        chat_frame.grid_columnconfigure(0, weight=1)
        chat_frame.grid_rowconfigure(1, weight=1) # Chat display row

        customtkinter.CTkLabel(chat_frame, text="💬 Chat Room",
                               font=("Arial", 16, "bold")).grid(row=0, column=0, pady=10, sticky="ew")

        # CTkTextbox widget for displaying messages
        self.chat_display = customtkinter.CTkTextbox(
            chat_frame,
            font=("Arial", 12),
            wrap="word",
            state="disabled"
        )
        self.chat_display.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # --- Message Input Section ---
        msg_frame = customtkinter.CTkFrame(chat_frame, fg_color="transparent")
        msg_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        msg_frame.grid_columnconfigure(0, weight=1)

        # Radio buttons for selecting message type (Public/Private)
        msg_type_frame = customtkinter.CTkFrame(msg_frame, fg_color="transparent")
        msg_type_frame.grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.msg_type = tkinter.StringVar(value="public")
        customtkinter.CTkRadioButton(msg_type_frame, text="📢 Public (TCP)",
                                     variable=self.msg_type, value="public",
                                     command=self.update_message_mode).pack(side="left", padx=(0, 15))
        customtkinter.CTkRadioButton(msg_type_frame, text="🔒 Private (UDP)",
                                     variable=self.msg_type, value="private",
                                     command=self.update_message_mode).pack(side="left")

        # Label to show the selected private message target
        self.private_target_frame = customtkinter.CTkFrame(msg_frame, fg_color="transparent")
        # this frame will be gridded in update_message_mode
        customtkinter.CTkLabel(self.private_target_frame, text="🎯 Target:",
                               font=("Arial", 10)).pack(side="left")
        self.target_user_label = customtkinter.CTkLabel(self.private_target_frame, text="None",
                                                        font=("Arial", 10, "bold"), text_color="#FF6B35")
        self.target_user_label.pack(side="left", padx=(5, 0))

        # Message entry box and send button
        msg_input_frame = customtkinter.CTkFrame(msg_frame, fg_color="transparent")
        msg_input_frame.grid(row=2, column=0, sticky="ew", pady=(5, 0))
        msg_input_frame.grid_columnconfigure(0, weight=1)
        msg_input_frame.grid_columnconfigure(1, weight=0)

        self.message_entry = customtkinter.CTkEntry(
            msg_input_frame, font=("Arial", 11), placeholder_text="Type your message here..."
        )
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message) # Allow sending with Enter key
        self.send_btn = customtkinter.CTkButton(
            msg_input_frame, text="Send", command=self.send_message, width=70
        )
        self.send_btn.grid(row=0, column=1, sticky="e")

    def setup_control_panel(self, parent):
        """
        Sets up the right panel containing user controls, connection buttons, and user list.

        Args:
            parent (customtkinter.CTkFrame): The parent widget for this area.
        """
        control_frame = customtkinter.CTkScrollableFrame(parent, label_text="⚙️ Control Panel",
                                                         label_font=("Arial", 16, "bold"))
        control_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        control_frame.grid_columnconfigure(0, weight=1)
        control_frame.grid_rowconfigure(6, weight=1) # The users_frame row will expand

        # Username input
        user_frame = customtkinter.CTkFrame(control_frame)
        user_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(0, 10))
        user_frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(user_frame, text="Username").grid(row=0, column=0, sticky="w", padx=10, pady=(5,0))
        self.username_entry = customtkinter.CTkEntry(user_frame, placeholder_text="Enter your username")
        self.username_entry.grid(row=1, column=0, sticky="ew", padx=10, pady=(0,10))

        # Port information display
        port_info_frame = customtkinter.CTkFrame(control_frame)
        port_info_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        port_info_frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(port_info_frame, text="Port Info").grid(row=0, column=0, sticky="w", padx=10, pady=(5,0))
        customtkinter.CTkLabel(port_info_frame, text=f"📢 TCP Public Chat: {self.tcp_port}",
                 font=("Arial", 9)).grid(row=1, column=0, sticky="w", padx=15, pady=2)
        customtkinter.CTkLabel(port_info_frame, text=f"🔒 UDP Private Msg: {self.udp_port}",
                 font=("Arial", 9)).grid(row=2, column=0, sticky="w", padx=15, pady=(2,5))

        # Connection controls
        server_frame = customtkinter.CTkFrame(control_frame)
        server_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        server_frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(server_frame, text="Connection").grid(row=0, column=0, sticky="w", padx=10, pady=(5,0))
        self.auto_connect_btn = customtkinter.CTkButton(server_frame, text="🚀 Auto-Connect", command=self.auto_connect,
                                                        font=("Arial", 12, "bold"))
        self.auto_connect_btn.grid(row=1, column=0, sticky="ew", pady=5, padx=10)
        self.disconnect_btn = customtkinter.CTkButton(server_frame, text="❌ Disconnect", command=self.disconnect_from_server,
                                                      fg_color="#DC3545", hover_color="#C82333")
        self.disconnect_btn.grid(row=2, column=0, sticky="ew", pady=(0, 10), padx=10)

        # Connection status label
        self.status_label = customtkinter.CTkLabel(control_frame, text="🔴 Disconnected", text_color="#DC3545")
        self.status_label.grid(row=3, column=0, sticky="ew", pady=5)

        # --- Performance Testing ---
        perf_frame = customtkinter.CTkFrame(control_frame)
        perf_frame.grid(row=4, column=0, sticky="ew", padx=10, pady=10)
        perf_frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(perf_frame, text="📊 Performance Tests").grid(row=0, column=0, sticky="w", padx=10, pady=(5,0))

        self.rtt_btn = customtkinter.CTkButton(perf_frame, text="Test TCP Latency (RTT)", command=self.run_tcp_rtt_test)
        self.rtt_btn.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        self.throughput_btn = customtkinter.CTkButton(perf_frame, text="Test TCP Throughput", command=self.run_throughput_test)
        self.throughput_btn.grid(row=2, column=0, sticky="ew", padx=10, pady=(0,10))

        # Network topology button
        self.topology_btn = customtkinter.CTkButton(control_frame, text="🌐 View Network Peers", command=self.show_network_topology)
        self.topology_btn.grid(row=5, column=0, sticky="ew", padx=10, pady=5)

        # Connected users list
        users_frame = customtkinter.CTkFrame(control_frame)
        users_frame.grid(row=6, column=0, sticky="nsew", padx=10, pady=5)
        users_frame.grid_columnconfigure(0, weight=1)
        users_frame.grid_rowconfigure(1, weight=1) # Scrollable listbox row

        customtkinter.CTkLabel(users_frame, text="👥 Connected Users").grid(row=0, column=0, sticky="w", padx=10, pady=(5,0))
        self.users_listbox = customtkinter.CTkScrollableFrame(users_frame, label_text="")
        self.users_listbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        # User list controls
        user_ctrl_frame = customtkinter.CTkFrame(users_frame, fg_color="transparent")
        user_ctrl_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 5))
        user_ctrl_frame.grid_columnconfigure(0, weight=1)
        user_ctrl_frame.grid_columnconfigure(1, weight=0)

        customtkinter.CTkButton(user_ctrl_frame, text="🔄 Refresh", command=self.refresh_user_list,
                                width=100).grid(row=0, column=0, sticky="w")
        customtkinter.CTkButton(user_ctrl_frame, text="💬 Select Private", command=self.select_user_for_private,
                                fg_color="#FF6B35", hover_color="#E05A2A", width=100).grid(row=0, column=1, sticky="e")

        # Initial state setup
        self.refresh_user_list()
        threading.Thread(target=self.check_server_on_startup, daemon=True).start()

    def update_message_mode(self):
        """Updates the UI to show or hide the private message target label."""
        if self.msg_type.get() == "private":
            self.private_target_frame.grid(row=1, column=0, sticky="w", pady=(0, 5))
        else:
            self.private_target_frame.grid_remove()

    def select_user_for_private(self, event=None):
        """
        Selects the first available user (not self) for private messaging.
        """
        try:
            # Pick the first one who isn't us
            other_users = [u for u in self.connected_users if u != self.current_username]
            if other_users:
                self.selected_user = other_users[0]
                self.target_user_label.configure(text=self.selected_user)
                self.msg_type.set("private")
                self.update_message_mode()
                self.add_message(f"[System] 🎯 Private target set to: {self.selected_user}", "system")
            else:
                messagebox.showinfo("Info", "No other users are available for private messaging.")
        except Exception as e:
            self.add_message(f"[Error] Failed to select user: {e}", "error")

    def select_user_from_list(self, username: str):
        """
        Sets the selected user from the list as the private message target.
        Triggered by clicking a user's button in the list.

        Args:
            username (str): The username of the user to select.
        """
        try:
            if username == self.current_username:
                messagebox.showwarning("Warning", "You cannot send a private message to yourself.")
                return

            if username:
                self.selected_user = username
                self.target_user_label.configure(text=username)
                self.msg_type.set("private")
                self.update_message_mode()
                self.add_message(f"[System] 🎯 Private target set to: {username}", "system")
            else:
                messagebox.showwarning("Warning", "Please select a valid user.")
        except Exception as e:
            self.add_message(f"[Error] Failed to select user from list: {e}", "error")

    def check_server_on_startup(self):
        """Checks if a local server is running at startup and informs the user."""
        time.sleep(1) # Wait for GUI to load
        try:
            with socket.create_connection(("localhost", self.server_port), timeout=2):
                pass
            self.add_message("[System] 🔍 A local server was found. Use 'Auto-Connect' to join.", "system")
        except (socket.timeout, ConnectionRefusedError):
            self.add_message("[System] 🚀 No local server found. Use 'Auto-Connect' to start one.", "system")

    def auto_connect(self):
        """
        Core connection logic: starts as a server if none is found,
        otherwise connects as a client.
        """
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username first.")
            return
        self.current_username = username

        # Check for an existing server on the local machine
        try:
            with socket.create_connection(("localhost", self.server_port), timeout=2):
                pass
            self.add_message("[System] 🔗 Connecting to existing local server...", "system")
            self.connect_as_client()
        except (socket.timeout, ConnectionRefusedError):
            self.add_message("[System] 🚀 Starting new server...", "system")
            self.start_as_server()

    def start_as_server(self):
        """Starts the TCP and UDP servers and configures the app for server mode."""
        try:
            # Start TCP public chat server
            self.tcp_server_thread = threading.Thread(target=self._start_tcp_server, daemon=True)
            self.tcp_server_thread.start()

            # Start UDP private message server
            self.udp_server = udp_server.UDPServer(port=self.udp_port)
            self.udp_server_thread = threading.Thread(target=self.udp_server.start, daemon=True)
            self.udp_server_thread.start()

            # The server host also needs a UDP socket to send private messages
            self.udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Register the server host itself as a UDP client
            time.sleep(0.5) # Wait for UDP server to bind
            udp_join_packet = build_packet(self.current_username, "join", "joined")
            self.udp_client_socket.sendto(udp_join_packet, ("localhost", self.udp_port))

            self.tcp_server = True
            self.status_label.configure(text="🟢 Server Mode (TCP+UDP)", text_color="#28A745")
            self.connected_users = [self.current_username]
            self.refresh_user_list()
            self.add_message(f"[System] ✅ Server started as '{self.current_username}'", "success")

            # Start background listeners
            threading.Thread(target=self.server_message_listener, daemon=True).start()
            threading.Thread(target=self.udp_private_listener, daemon=True).start()

            # Start peer discovery service
            self.topology_discovery.start_discovery(self.current_username)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")

    def _start_tcp_server(self):
        """Helper function to run the TCP server in a thread."""
        server.set_server_username(self.current_username)
        server.start_server_with_port(self.server_port)

    def connect_as_client(self):
        """Connects to the existing servers as a client."""
        try:
            # Establish TCP connection for public chat
            self.tcp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client_socket.connect(("localhost", self.server_port))
            tcp_join_packet = build_packet(self.current_username, "join", "joined")
            send_packet(self.tcp_client_socket, tcp_join_packet)

            # Create a UDP socket for sending/receiving private messages
            self.udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Register with the UDP server
            udp_join_packet = build_packet(self.current_username, "join", "joined")
            self.udp_client_socket.sendto(udp_join_packet, ("localhost", self.udp_port))

            self.is_client_mode = True
            self.status_label.configure(text="🟢 Client Mode (TCP+UDP)", text_color="#28A745")
            self.add_message(f"[System] ✅ Connected as '{self.current_username}'", "success")

            # Start background listeners
            threading.Thread(target=self.client_message_listener, daemon=True).start()
            threading.Thread(target=self.udp_private_listener, daemon=True).start()

            # Start peer discovery service
            self.topology_discovery.start_discovery(self.current_username)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to server: {e}")

    def server_message_listener(self):
        """
        Listens for messages from the server module's queue.
        (For server-host only)
        """
        while self.tcp_server:
            try:
                for msg in server.get_server_messages():
                    if msg["type"] == "message" and msg["sender"] != self.current_username:
                        self.add_message(f"{msg['sender']}: {msg['text']}")
                    elif msg["type"] == "userlist":
                        all_users = [self.current_username] + msg["users"]
                        self.update_user_list(all_users)
                time.sleep(0.1)
            except Exception:
                break

    def client_message_listener(self):
        """Listens for incoming TCP messages from the server. (For clients only)"""
        from protocol import parse_packet
        while self.is_client_mode and self.tcp_client_socket:
            try:
                data = receive_packet(self.tcp_client_socket)
                if not data:
                    self.add_message("[System] ❌ Server connection lost.", "error")
                    break
                
                packet = parse_packet(data)
                if packet:
                    sender = packet["header"]["sender"]
                    text = packet["payload"]["text"]
                    msg_type = packet["header"]["type"]

                    if msg_type == "message":
                        if sender == "SERVER":
                            self.add_message(f"[System] {text}", "system")
                        else: # Don't display our own echoed messages
                            self.add_message(f"{sender}: {text}")
                    elif msg_type == "userlist":
                        if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
                            self.update_user_list(packet["payload"]["extra"]["users"])
                            self.add_message("[System] User list updated.", "system")
                    elif msg_type == "pong":
                        # RTT test pong received
                        ping_id = text
                        if ping_id in self.rtt_tests:
                            send_time = self.rtt_tests.pop(ping_id)
                            rtt = (time.time() - send_time) * 1000  # in ms
                            self.rtt_results.append(rtt)

                            if len(self.rtt_results) % 10 == 0:
                                self.add_message(f"[Perf] RTT progress: {len(self.rtt_results)}/50 pongs received.", "system")

                            if len(self.rtt_results) == 50:
                                avg_rtt = sum(self.rtt_results) / len(self.rtt_results)
                                self.add_message(f"[Perf] ✅ TCP RTT test complete. Average RTT: {avg_rtt:.2f} ms", "success")
                    elif msg_type == "throughput_echo":
                        # Throughput echo received
                        if self.throughput_start_time > 0:
                            self.throughput_packets_received += 1

                            if self.throughput_packets_received == self.throughput_total_packets:
                                end_time = time.time()
                                duration = end_time - self.throughput_start_time
                                
                                # Calculate total data transferred based on one packet's size
                                single_packet_size_bytes = len(data)
                                total_data_bytes = single_packet_size_bytes * self.throughput_total_packets
                                
                                # Data travels client -> server -> client, so total distance is 2x
                                total_data_megabits = (total_data_bytes * 2 * 8) / (1024 * 1024)
                                total_data_megabytes = (total_data_bytes / (1024 * 1024)) * 2

                                # Prevent division by zero
                                if duration > 0:
                                    throughput_mbps = total_data_megabits / duration
                                else:
                                    throughput_mbps = float('inf')

                                self.add_message(f"[Perf] ✅ Throughput test complete.", "success")
                                self.add_message(f"[Perf] Transfer of {total_data_megabytes:.2f} MB (round-trip) took {duration:.2f}s.", "system")
                                self.add_message(f"[Perf] Effective throughput: {throughput_mbps:.2f} Mbps.", "success")
                                
                                # Reset test state
                                self.throughput_start_time = 0
                                self.throughput_packets_received = 0
                                self.throughput_total_packets = 0
            except Exception:
                if self.is_client_mode:
                    self.add_message("[System] ❌ Connection error.", "error")
                break

    def disconnect_from_server(self):
        """Handles disconnection from servers and resets the application state."""
        if not self.current_username: return # Already disconnected

        from protocol import build_packet

        # A client should notify the server that it's leaving.
        # The server host should not, as it will shut down the server anyway.
        if self.is_client_mode:
            try:
                leave_packet = build_packet(self.current_username, "leave", "left")
                if self.tcp_client_socket:
                    send_packet(self.tcp_client_socket, leave_packet)
                if self.udp_client_socket:
                    self.udp_client_socket.sendto(leave_packet, ("localhost", self.udp_port))
            except Exception as e:
                # Use logging for errors that happen during shutdown
                logging.error(f"Error sending leave packets: {e}")

        # Stop server threads if we are the host
        if self.tcp_server:
            server.stop_server()
            self.tcp_server = None
        if self.udp_server:
            self.udp_server.stop()
            self.udp_server = None
        
        # Always stop the discovery service
        self.topology_discovery.stop_discovery()

        # Close client sockets if they exist
        if self.tcp_client_socket:
            self.tcp_client_socket.close()
        if self.udp_client_socket:
            self.udp_client_socket.close()

        # Reset all state variables
        self.is_client_mode = False
        self.tcp_client_socket = None
        self.udp_client_socket = None
        self.current_username = ""
        self.connected_users = []
        self.selected_user = None

        # Performance test state
        self.rtt_tests.clear()
        self.rtt_results.clear()
        self.throughput_start_time = 0
        self.throughput_packets_received = 0
        self.throughput_total_packets = 0

        # Reset UI elements
        self.status_label.configure(text="🔴 Disconnected", text_color="#DC3545")
        self.target_user_label.configure(text="None")
        self.username_entry.configure(state="normal") # Re-enable username entry
        self.refresh_user_list()
        
        # Don't add a message if the root window is destroyed
        if self.master.winfo_exists():
            self.add_message("[System] ✅ Disconnected successfully.", "success")

    def send_message(self, event=None):
        """
        Sends a message based on the current UI state (public or private).
        """
        message = self.message_entry.get().strip()
        if not message: return
        if not self.current_username:
            messagebox.showerror("Error", "You must be connected to send messages.")
            return

        if self.msg_type.get() == "public":
            self.send_public_message(message)
        else: # Private message
            self.send_private_message(message)

        self.message_entry.delete(0, tkinter.END)

    def send_public_message(self, message: str):
        """
        Sends a public message via TCP.

        Args:
            message (str): The text of the message to send.
        """
        try:
            packet = build_packet(self.current_username, "message", message)
            if self.tcp_server: # If we are the server, broadcast it locally
                server.broadcast(packet)
                self.add_message(f"You (Public): {message}")
            elif self.is_client_mode and self.tcp_client_socket: # If client, send to server
                send_packet(self.tcp_client_socket, packet)
                self.add_message(f"You (Public): {message}")
        except Exception as e:
            self.add_message(f"[Error] Failed to send public message: {e}", "error")

    def send_private_message(self, message: str):
        """
        Sends a private message via UDP.

        Args:
            message (str): The text of the message to send.
        """
        if not self.selected_user:
            messagebox.showwarning("Warning", "Please select a user to send a private message.")
            return
        if self.selected_user == self.current_username:
            messagebox.showwarning("Warning", "You cannot send a private message to yourself.")
            return

        try:
            # Format the text for the UDP server to parse the target user
            formatted_text = f"@{self.selected_user}: {message}"
            packet = build_packet(self.current_username, "private_message", formatted_text)
            if self.udp_client_socket:
                self.udp_client_socket.sendto(packet, ("localhost", self.udp_port))
                self.add_message(f"You -> {self.selected_user}: {message}", "private")
        except Exception as e:
            self.add_message(f"[Error] Failed to send private message: {e}", "error")

    def udp_private_listener(self):
        """Listens for incoming UDP messages (private messages and server confirmations)."""
        from protocol import parse_packet, build_packet
        while self.is_client_mode or self.tcp_server:
            try:
                if self.udp_client_socket:
                    self.udp_client_socket.settimeout(3.0) # Timeout to prevent blocking
                    data, addr = self.udp_client_socket.recvfrom(1024)
                    
                    packet = parse_packet(data)
                    if packet:
                        # Acknowledge reliable packets
                        if "seq" in packet["header"]:
                            ack_packet = build_packet("CLIENT", "ack", seq=packet["header"]["seq"])
                            self.udp_client_socket.sendto(ack_packet, addr)

                        msg_type = packet["header"]["type"]
                        sender = packet["header"]["sender"]
                        text = packet["payload"]["text"]

                        if msg_type == "private_message" and sender != self.current_username:
                            self.add_message(f"{text}", "private")
                        elif msg_type == "message" and sender == "SERVER":
                            # These are system messages from the UDP server (e.g., confirmations, errors)
                            self.add_message(f"[System] {text}", "system")
            except socket.timeout:
                continue # Normal, allows the loop to check `is_running`
            except Exception:
                if self.is_client_mode or self.tcp_server:
                    pass # Suppress errors if we are shutting down
                break

    def add_message(self, message: str, tag: str = None):
        """
        Adds a message to the chat display widget, with optional color-coding.

        Args:
            message (str): The message string to add.
            tag (str, optional): A tag for applying color, e.g., "error", "private".
        """
        if not self.master.winfo_exists(): return
        self.chat_display.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")

        # Configure tags for colored text
        self.chat_display.tag_config("error", foreground="#DC3545")
        self.chat_display.tag_config("success", foreground="#28A745")
        self.chat_display.tag_config("system", foreground="gray")
        self.chat_display.tag_config("private", foreground="#FF6B35")

        self.chat_display.insert("end", f"[{timestamp}] ")
        self.chat_display.insert("end", f"{message}\n", tag)
        self.chat_display.see("end") # Scroll to bottom
        self.chat_display.configure(state="disabled")
    
    def show_network_topology(self):
        """Opens a new window to display the network peer list."""
        if not self.current_username:
            messagebox.showwarning("Warning", "You must be connected to view network peers.")
            return

        # Create the topology window
        topology_window = customtkinter.CTkToplevel(self.master)
        topology_window.title("Network Peer List")
        topology_window.geometry("600x500")
        topology_window.grid_columnconfigure(0, weight=1)
        topology_window.grid_rowconfigure(1, weight=1)

        customtkinter.CTkLabel(topology_window, text="🌐 Discovered Network Peers",
                               font=("Arial", 16, "bold")).grid(row=0, column=0, pady=10)

        # ScrolledText widget to display peer info
        peer_text = customtkinter.CTkTextbox(
            topology_window,
            font=("Courier", 11), height=20, state="disabled"
        )
        peer_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        
        # Auto-refreshing display logic using a closure
        def update_display():
            if not topology_window.winfo_exists(): return
            
            peer_list = self.topology_discovery.get_peer_list()
            
            peer_text.configure(state="normal")
            peer_text.delete(1.0, "end")
            
            if not peer_list:
                peer_text.insert("end", "🔍 Searching for other peers...")
            else:
                for peer in peer_list:
                    status_icon = "🟢" if peer["status"] == "active" else "🔴"
                    rtt_str = f"{peer['rtt']:.1f}ms" if peer.get('rtt', 0) > 0 else "N/A"
                    peer_text.insert("end", f"{status_icon} {peer['peer_id']}\n")
                    peer_text.insert("end", f"   ├─ Address: {peer['ip']}:{peer['port']}\n")
                    peer_text.insert("end", f"   └─ RTT: {rtt_str}\n\n")
            
            peer_text.configure(state="disabled")
            topology_window.after(3000, update_display) # Schedule next update
        
        update_display() # Initial call
    
    def refresh_user_list(self):
        """Updates the user listbox with the current list of connected users."""
        if self.tcp_server:
            try:
                # If we are the server, get the list from the server module
                # and add our own username.
                connected_users = server.get_connected_users()
                self.connected_users = [self.current_username] + connected_users
            except Exception:
                self.connected_users = [self.current_username] if self.current_username else []

        # Clear old widgets from the scrollable frame
        for widget in self.users_listbox.winfo_children():
            widget.destroy()
        
        self.users_listbox.grid_columnconfigure(0, weight=1)
        
        if not self.current_username:
            customtkinter.CTkLabel(self.users_listbox, text="🔴 Not connected").grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        else:
            sorted_users = sorted(list(set(self.connected_users)))
            for i, user in enumerate(sorted_users):
                text = f"👤 {user} (You)" if user == self.current_username else f"👥 {user}"
                btn = customtkinter.CTkButton(
                    self.users_listbox,
                    text=text,
                    fg_color="transparent",
                    anchor="w",
                    command=lambda u=user: self.select_user_from_list(u)
                )
                btn.grid(row=i, column=0, sticky="ew", padx=5, pady=2)

            if len(sorted_users) <= 1:
                customtkinter.CTkLabel(self.users_listbox, text="🔍 No other users online",
                                       text_color="gray").grid(row=len(sorted_users), column=0, padx=5, pady=5, sticky="ew")
    
    def update_user_list(self, users: list):
        """
        Callback to update the internal user list and refresh the display.

        Args:
            users (list): The new list of usernames.
        """
        self.connected_users = users
        self.refresh_user_list()

    def run_tcp_rtt_test(self):
        """Runs a TCP latency test by sending 50 pings and measuring response time."""
        if not self.is_client_mode or not self.tcp_client_socket:
            messagebox.showwarning("Warning", "You must be connected as a client to run this test.")
            return

        self.rtt_tests.clear()
        self.rtt_results.clear()
        self.add_message("[Perf] 🚀 Starting TCP RTT test (50 pings)...", "system")

        def test_thread():
            try:
                for i in range(50):
                    ping_id = f"rtt_{time.time()}"
                    self.rtt_tests[ping_id] = time.time()
                    # The ping text is used as a unique ID to match the pong
                    packet = build_packet(self.current_username, "ping", text=ping_id)
                    send_packet(self.tcp_client_socket, packet)
                    time.sleep(0.1)  # 100ms interval between pings
            except Exception as e:
                self.add_message(f"[Error] RTT test failed: {e}", "error")

        threading.Thread(target=test_thread, daemon=True).start()

    def run_throughput_test(self):
        """Runs a TCP throughput test by sending a burst of large packets."""
        if not self.is_client_mode or not self.tcp_client_socket:
            messagebox.showwarning("Warning", "You must be connected as a client to run this test.")
            return
        
        if self.throughput_start_time > 0:
            messagebox.showwarning("Warning", "A throughput test is already in progress.")
            return

        self.throughput_total_packets = 200  # Send a burst of 200 packets
        self.throughput_packets_received = 0
        self.add_message(f"[Perf] 🚀 Starting TCP throughput test ({self.throughput_total_packets} x 512KB echo)...", "system")
        
        def test_thread():
            try:
                # Prepare a large payload.
                data_size_bytes = 512 * 1024  # 512 KB
                payload = "T" * data_size_bytes
                packet = build_packet(self.current_username, "throughput_echo", text=payload)
                
                self.throughput_start_time = time.time()
                for _ in range(self.throughput_total_packets):
                    send_packet(self.tcp_client_socket, packet)
            except Exception as e:
                self.add_message(f"[Error] Throughput test failed: {e}", "error")
                # Reset test state on failure
                self.throughput_start_time = 0
                self.throughput_packets_received = 0
                self.throughput_total_packets = 0

        threading.Thread(target=test_thread, daemon=True).start()

# Main application entry point
if __name__ == "__main__":
    try:
        root = customtkinter.CTk()
        app = SimpleChatApp(root)
        
        # Ensure graceful shutdown
        def on_closing():
            if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
                app.disconnect_from_server()
                root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
    except Exception as e:
        logging.error(f"Application failed to start: {e}")
        input("Press Enter to exit...")