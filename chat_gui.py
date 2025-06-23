"""
Graphical User Interface for the Chat Application

This module provides the main GUI for the chat application, built with Tkinter.
It integrates the TCP (public chat), UDP (private chat), and topology
discovery services into a cohesive user interface.
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import socket

# Import the backend modules
import server
import udp_server
import topology_discovery
from protocol import build_packet

# A simple color theme for the GUI
THEME = {
    "bg": "#2B2B2B",
    "panel_bg": "#3C3C3C",
    "button_bg": "#007ACC",
    "button_fg": "#FFFFFF",
    "entry_bg": "#4D4D4D",
    "text_color": "#FFFFFF",
    "success": "#28A745",
    "error": "#DC3545",
    "muted": "#CCCCCC",
    "private": "#FF6B35"
}

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
            master (tk.Tk): The root Tkinter window.
        """
        self.master = master
        self.master.title("🎯 Network Chat Application - TCP/UDP & Topology Discovery")
        self.master.geometry("1000x700")
        self.master.configure(bg=THEME["bg"])

        # Connection state variables
        self.tcp_server = None
        self.udp_server = None
        self.tcp_server_thread = None
        self.udp_server_thread = None

        # Topology discovery module instance
        self.topology_discovery = topology_discovery.topology_discovery

        # Client mode state variables
        self.client_socket = None # Deprecated, use tcp_client_socket
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

        self.setup_ui()

    def find_available_port(self, start_port=12345) -> int:
        """
        Finds an available port for both TCP and UDP.

        Args:
            start_port (int): The port number to start searching from.

        Returns:
            int: An available port number.
        """
        import socket
        for port in range(start_port, start_port + 100):
            try:
                # Test TCP port
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
                    tcp_sock.bind(('', port))
                # Test UDP port
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                    udp_sock.bind(('', port))
                return port
            except OSError:
                continue
        # Fallback to a random port if none in the range are free
        with socket.socket() as sock:
            sock.bind(('', 0))
            return sock.getsockname()[1]

    def setup_ui(self):
        """Sets up the main user interface layout."""
        main_frame = tk.Frame(self.master, bg=THEME["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # UI is split into a left chat area and a right control panel
        self.setup_chat_area(main_frame)
        self.setup_control_panel(main_frame)

    def setup_chat_area(self, parent):
        """
        Sets up the left panel containing the chat display and message input.

        Args:
            parent (tk.Frame): The parent widget for this area.
        """
        chat_frame = tk.Frame(parent, bg=THEME["panel_bg"], relief="raised", bd=1)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        tk.Label(chat_frame, text="💬 Chat Room",
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 14, "bold")).pack(pady=10)

        # ScrolledText widget for displaying messages
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            bg=THEME["bg"], fg=THEME["text_color"],
            font=("Arial", 11),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # --- Message Input Section ---
        msg_frame = tk.Frame(chat_frame, bg=THEME["panel_bg"])
        msg_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Radio buttons for selecting message type (Public/Private)
        msg_type_frame = tk.Frame(msg_frame, bg=THEME["panel_bg"])
        msg_type_frame.pack(fill=tk.X, pady=(0, 5))
        self.msg_type = tk.StringVar(value="public")
        tk.Radiobutton(msg_type_frame, text="📢 Public (TCP)",
                      variable=self.msg_type, value="public",
                      bg=THEME["panel_bg"], fg=THEME["text_color"],
                      selectcolor=THEME["success"], activebackground=THEME["panel_bg"],
                      command=self.update_message_mode).pack(side=tk.LEFT, padx=(0, 15))
        tk.Radiobutton(msg_type_frame, text="🔒 Private (UDP)",
                      variable=self.msg_type, value="private",
                      bg=THEME["panel_bg"], fg=THEME["text_color"],
                      selectcolor=THEME["private"], activebackground=THEME["panel_bg"],
                      command=self.update_message_mode).pack(side=tk.LEFT)

        # Label to show the selected private message target
        self.private_target_frame = tk.Frame(msg_frame, bg=THEME["panel_bg"])
        tk.Label(self.private_target_frame, text="🎯 Target:",
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 10)).pack(side=tk.LEFT)
        self.target_user_label = tk.Label(self.private_target_frame, text="None",
                                         bg=THEME["panel_bg"], fg=THEME["private"],
                                         font=("Arial", 10, "bold"))
        self.target_user_label.pack(side=tk.LEFT, padx=(5, 0))

        # Message entry box and send button
        msg_input_frame = tk.Frame(msg_frame, bg=THEME["panel_bg"])
        msg_input_frame.pack(fill=tk.X, pady=(5, 0))
        self.message_entry = tk.Entry(
            msg_input_frame, bg=THEME["entry_bg"], fg=THEME["text_color"], font=("Arial", 11)
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message) # Allow sending with Enter key
        self.send_btn = tk.Button(
            msg_input_frame, text="Send", command=self.send_message,
            bg=THEME["button_bg"], fg=THEME["button_fg"], font=("Arial", 10)
        )
        self.send_btn.pack(side=tk.RIGHT)

    def setup_control_panel(self, parent):
        """
        Sets up the right panel containing user controls, connection buttons, and user list.

        Args:
            parent (tk.Frame): The parent widget for this area.
        """
        control_frame = tk.Frame(parent, bg=THEME["panel_bg"], relief="raised", bd=1, width=250)
        control_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        control_frame.pack_propagate(False) # Prevent the frame from resizing to fit content

        tk.Label(control_frame, text="⚙️ Control Panel",
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 14, "bold")).pack(pady=10)

        # Username input
        user_frame = tk.LabelFrame(control_frame, text="Username", bg=THEME["panel_bg"], fg=THEME["text_color"])
        user_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.username_entry = tk.Entry(user_frame, bg=THEME["entry_bg"], fg=THEME["text_color"])
        self.username_entry.pack(fill=tk.X, padx=5, pady=5)

        # Port information display
        port_info_frame = tk.LabelFrame(control_frame, text="Port Info", bg=THEME["panel_bg"], fg=THEME["text_color"])
        port_info_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Label(port_info_frame, text=f"📢 TCP Public Chat: {self.tcp_port}",
                 bg=THEME["panel_bg"], fg=THEME["text_color"], font=("Arial", 9)).pack(anchor="w", padx=5)
        tk.Label(port_info_frame, text=f"🔒 UDP Private Msg: {self.udp_port}",
                 bg=THEME["panel_bg"], fg=THEME["text_color"], font=("Arial", 9)).pack(anchor="w", padx=5)

        # Connection controls
        server_frame = tk.LabelFrame(control_frame, text="Connection", bg=THEME["panel_bg"], fg=THEME["text_color"])
        server_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.auto_connect_btn = tk.Button(server_frame, text="🚀 Auto-Connect", command=self.auto_connect,
                                          bg=THEME["success"], fg=THEME["button_fg"], font=("Arial", 11, "bold"))
        self.auto_connect_btn.pack(fill=tk.X, pady=2, padx=5)
        self.disconnect_btn = tk.Button(server_frame, text="❌ Disconnect", command=self.disconnect_from_server,
                                        bg=THEME["error"], fg=THEME["button_fg"], font=("Arial", 10))
        self.disconnect_btn.pack(fill=tk.X, pady=5, padx=5)

        # Connection status label
        self.status_label = tk.Label(control_frame, text="🔴 Disconnected", bg=THEME["panel_bg"], fg=THEME["error"])
        self.status_label.pack(pady=10)

        # Network topology button
        self.topology_btn = tk.Button(control_frame, text="🌐 View Network Peers", command=self.show_network_topology,
                                      bg=THEME["button_bg"], fg=THEME["button_fg"])
        self.topology_btn.pack(fill=tk.X, padx=10, pady=5)

        # Connected users list
        users_frame = tk.LabelFrame(control_frame, text="👥 Connected Users", bg=THEME["panel_bg"], fg=THEME["text_color"])
        users_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.users_listbox = tk.Listbox(users_frame, bg=THEME["bg"], fg=THEME["text_color"],
                                        font=("Arial", 10), height=8, selectbackground=THEME["button_bg"])
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.users_listbox.bind("<Double-Button-1>", self.select_user_from_list)

        # User list controls
        user_ctrl_frame = tk.Frame(users_frame, bg=THEME["panel_bg"])
        user_ctrl_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        tk.Button(user_ctrl_frame, text="🔄 Refresh", command=self.refresh_user_list,
                  bg=THEME["button_bg"], fg=THEME["button_fg"], font=("Arial", 9)).pack(side=tk.LEFT)
        tk.Button(user_ctrl_frame, text="💬 Select Private", command=self.select_user_for_private,
                  bg=THEME["private"], fg=THEME["button_fg"], font=("Arial", 9)).pack(side=tk.RIGHT)

        # Initial state setup
        self.refresh_user_list()
        threading.Thread(target=self.check_server_on_startup, daemon=True).start()

    def update_message_mode(self):
        """Updates the UI to show or hide the private message target label."""
        if self.msg_type.get() == "private":
            self.private_target_frame.pack(fill=tk.X, pady=(0, 5))
        else:
            self.private_target_frame.pack_forget()

    def select_user_for_private(self, event=None):
        """
        Selects a user for private messaging from the listbox.
        If no user is selected in the list, it tries to select the first available user.

        Args:
            event: The event object from the button click (optional).
        """
        try:
            selection = self.users_listbox.curselection()
            if selection:
                self.select_user_from_list()
            else: # If no user is highlighted, pick the first one who isn't us
                other_users = [u for u in self.connected_users if u != self.current_username]
                if other_users:
                    self.selected_user = other_users[0]
                    self.target_user_label.config(text=self.selected_user)
                    self.msg_type.set("private")
                    self.update_message_mode()
                    self.add_message(f"[System] 🎯 Private target set to: {self.selected_user}", "muted")
                else:
                    messagebox.showinfo("Info", "No other users are available for private messaging.")
        except Exception as e:
            self.add_message(f"[Error] Failed to select user: {e}", "error")

    def select_user_from_list(self, event=None):
        """
        Sets the selected user from the listbox as the private message target.
        Triggered by double-clicking a user or the 'Select Private' button.

        Args:
            event: The event object from the listbox click (optional).
        """
        try:
            selection = self.users_listbox.curselection()
            if not selection: return

            selected_line = self.users_listbox.get(selection[0])
            # Parse the username, ignoring icons and "(You)"/"(Sen)" text
            if " (You)" in selected_line or " (Sen)" in selected_line:
                messagebox.showwarning("Warning", "You cannot send a private message to yourself.")
                return
            if "🔍" in selected_line or "🔴" in selected_line: return

            username = selected_line.replace("👥 ", "").replace("👤 ", "").strip()

            if username and username != self.current_username:
                self.selected_user = username
                self.target_user_label.config(text=username)
                self.msg_type.set("private")
                self.update_message_mode()
                self.add_message(f"[System] 🎯 Private target set to: {username}", "muted")
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
            self.add_message("[System] 🔍 A local server was found. Use 'Auto-Connect' to join.", "muted")
        except (socket.timeout, ConnectionRefusedError):
            self.add_message("[System] 🚀 No local server found. Use 'Auto-Connect' to start one.", "muted")

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
            self.add_message("[System] 🔗 Connecting to existing local server...", "muted")
            self.connect_as_client()
        except (socket.timeout, ConnectionRefusedError):
            self.add_message("[System] 🚀 Starting new server...", "muted")
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
            self.status_label.config(text="🟢 Server Mode (TCP+UDP)", fg=THEME["success"])
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
            self.tcp_client_socket.send(tcp_join_packet)

            # Create a UDP socket for sending/receiving private messages
            self.udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Register with the UDP server
            udp_join_packet = build_packet(self.current_username, "join", "joined")
            self.udp_client_socket.sendto(udp_join_packet, ("localhost", self.udp_port))

            self.is_client_mode = True
            self.status_label.config(text="🟢 Client Mode (TCP+UDP)", fg=THEME["success"])
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
        from protocol import parse_packet, MAX_PACKET_SIZE
        while self.is_client_mode and self.tcp_client_socket:
            try:
                data = self.tcp_client_socket.recv(MAX_PACKET_SIZE)
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
                            self.add_message(f"[System] {text}", "muted")
                        else: # Don't display our own echoed messages
                            self.add_message(f"{sender}: {text}")
                    elif msg_type == "userlist":
                        if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
                            self.update_user_list(packet["payload"]["extra"]["users"])
                            self.add_message("[System] User list updated.", "muted")
            except Exception:
                if self.is_client_mode:
                    self.add_message("[System] ❌ Connection error.", "error")
                break

    def disconnect_from_server(self):
        """Handles disconnection from servers and resets the application state."""
        try:
            from protocol import build_packet
            # Send leave packets
            if self.tcp_client_socket:
                leave_packet = build_packet(self.current_username, "leave", "left")
                self.tcp_client_socket.send(leave_packet)
                self.tcp_client_socket.close()
            if self.udp_client_socket and self.current_username:
                leave_packet = build_packet(self.current_username, "leave", "left")
                self.udp_client_socket.sendto(leave_packet, ("localhost", self.udp_port))
                self.udp_client_socket.close()

            # Stop server threads if we are the host
            if self.tcp_server: server.stop_server()
            if self.udp_server: self.udp_server.stop()
            # Stop discovery service
            self.topology_discovery.stop_discovery()

            # Reset all state variables
            self.is_client_mode = False
            self.tcp_server = None
            self.udp_server = None
            self.tcp_client_socket = None
            self.udp_client_socket = None
            self.current_username = ""
            self.connected_users = []
            self.selected_user = None

            # Reset UI elements
            self.status_label.config(text="🔴 Disconnected", fg=THEME["error"])
            self.target_user_label.config(text="None")
            self.refresh_user_list()
            self.add_message("[System] ✅ Disconnected successfully.", "success")
        except Exception as e:
            self.add_message(f"[Error] An error occurred during disconnection: {e}", "error")

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

        self.message_entry.delete(0, tk.END)

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
                self.tcp_client_socket.send(packet)
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
                            self.add_message(f"[System] {text}", "muted")
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
        self.chat_display.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")

        # Configure tags for colored text
        self.chat_display.tag_config("error", foreground=THEME["error"])
        self.chat_display.tag_config("success", foreground=THEME["success"])
        self.chat_display.tag_config("muted", foreground=THEME["muted"])
        self.chat_display.tag_config("private", foreground=THEME["private"])

        self.chat_display.insert(tk.END, f"[{timestamp}] ")
        self.chat_display.insert(tk.END, f"{message}\n", tag)
        self.chat_display.see(tk.END) # Scroll to bottom
        self.chat_display.config(state=tk.DISABLED)
    
    def show_network_topology(self):
        """Opens a new window to display the network peer list."""
        if not self.current_username:
            messagebox.showwarning("Warning", "You must be connected to view network peers.")
            return

        # Create the topology window
        topology_window = tk.Toplevel(self.master)
        topology_window.title("Network Peer List")
        topology_window.geometry("600x500")
        topology_window.configure(bg=THEME["bg"])

        tk.Label(topology_window, text="🌐 Discovered Network Peers",
                 bg=THEME["bg"], fg=THEME["text_color"], font=("Arial", 16, "bold")).pack(pady=10)

        # ScrolledText widget to display peer info
        peer_text = scrolledtext.ScrolledText(
            topology_window, bg=THEME["bg"], fg=THEME["text_color"],
            font=("Courier", 11), height=20, state=tk.DISABLED
        )
        peer_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Auto-refreshing display logic
        def update_display():
            if not topology_window.winfo_exists(): return
            
            peer_list = self.topology_discovery.get_peer_list()
            
            peer_text.config(state=tk.NORMAL)
            peer_text.delete(1.0, tk.END)
            
            if not peer_list:
                peer_text.insert(tk.END, "🔍 Searching for other peers...")
            else:
                for peer in peer_list:
                    status_icon = "🟢" if peer["status"] == "active" else "🔴"
                    rtt_str = f"{peer['rtt']:.1f}ms" if peer.get('rtt', 0) > 0 else "N/A"
                    peer_text.insert(tk.END, f"{status_icon} {peer['peer_id']}\n")
                    peer_text.insert(tk.END, f"   ├─ Address: {peer['ip']}:{peer['port']}\n")
                    peer_text.insert(tk.END, f"   └─ RTT: {rtt_str}\n\n")
            
            peer_text.config(state=tk.DISABLED)
            topology_window.after(3000, update_display) # Schedule next update
        
        update_display() # Initial call
    
    def refresh_peer_display(self, peer_text_widget, info_label_widget):
        """
        Refreshes the content of the peer display window.

        Args:
            peer_text_widget (tk.scrolledtext): The widget to update.
            info_label_widget (tk.Label): The label to update with stats.
        """
        try:
            if not peer_text_widget.winfo_exists(): return
            topology_data = self.topology_discovery.get_network_topology()
            peer_list = self.topology_discovery.get_peer_list()
            info_label_widget.config(text=f"Total Peers: {len(peer_list)} | Your ID: {topology_data.get('local_peer', 'N/A')}")
            self.update_peer_display(peer_text_widget, peer_list, topology_data)
        except tk.TclError: # Window was closed
            return
    
    def start_peer_auto_refresh(self, peer_text_widget, info_label_widget):
        """
        Starts the auto-refresh loop for the peer display window.
        
        Args:
            peer_text_widget (tk.scrolledtext): The widget to update.
            info_label_widget (tk.Label): The label to update with stats.
        """
        try:
            if not peer_text_widget.winfo_exists(): return # Stop if window is closed
            self.refresh_peer_display(peer_text_widget, info_label_widget)
            self.master.after(5000, lambda: self.start_peer_auto_refresh(peer_text_widget, info_label_widget))
        except tk.TclError: # Window was closed
            return
    
    def update_peer_display(self, peer_text_widget, peer_list, topology_data):
        """
        Updates the peer display text widget with the latest peer data.

        Args:
            peer_text_widget (tk.scrolledtext): The widget to update.
            peer_list (list): The list of discovered peers.
            topology_data (dict): The full topology data dictionary.
        """
        peer_text_widget.config(state=tk.NORMAL)
        peer_text_widget.delete(1.0, tk.END)
        
        peer_text_widget.insert(tk.END, "🌐 NETWORK PEER LIST\n", ("title",))
        peer_text_widget.insert(tk.END, "="*50 + "\n\n")
        
        local_peer = topology_data.get("local_peer", "N/A")
        peer_text_widget.insert(tk.END, f"📍 Your Peer ID: {local_peer}\n")
        
        if not peer_list:
            peer_text_widget.insert(tk.END, "\n🔍 No other peers discovered yet.\n")
        else:
            peer_text_widget.insert(tk.END, f"\n👥 Discovered Peers ({len(peer_list)}):\n")
            peer_text_widget.insert(tk.END, "-"*40 + "\n\n")
            for i, peer in enumerate(peer_list, 1):
                status_icon = "🟢" if peer["status"] == "active" else "🔴"
                peer_text_widget.insert(tk.END, f"{i}. {status_icon} {peer['peer_id']}\n")
                peer_text_widget.insert(tk.END, f"   ├─ IP: {peer['ip']}:{peer['port']}\n")
                peer_text_widget.insert(tk.END, f"   └─ Status: {peer['status'].title()}\n\n")
        
        peer_text_widget.config(state=tk.DISABLED)

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
        
        self.users_listbox.delete(0, tk.END)
        
        if not self.current_username:
            self.users_listbox.insert(tk.END, "🔴 Not connected")
        else:
            for user in sorted(self.connected_users):
                if user == self.current_username:
                    self.users_listbox.insert(tk.END, f"👤 {user} (You)")
                else:
                    self.users_listbox.insert(tk.END, f"👥 {user}")
            if len(self.connected_users) <= 1:
                self.users_listbox.insert(tk.END, "🔍 No other users online")
    
    def update_user_list(self, users: list):
        """
        Callback to update the internal user list and refresh the display.

        Args:
            users (list): The new list of usernames.
        """
        self.connected_users = users
        self.refresh_user_list()

# Main application entry point
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SimpleChatApp(root)
        
        # Ensure graceful shutdown
        def on_closing():
            if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
                app.disconnect_from_server()
                root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
    except Exception as e:
        print(f"Application failed to start: {e}")
        input("Press Enter to exit...")