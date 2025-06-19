"""
Basit Chat Arayüzü (Tkinter GUI)
- TCP ve UDP chat desteği
- Kullanıcı listesi
- Temel durum gösterimi
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time

# Sunucu modüllerini import et
import server
import udp_server
import topology_discovery

# Basit tema renkleri
THEME = {
    "bg": "#2B2B2B",
    "panel_bg": "#3C3C3C", 
    "button_bg": "#007ACC",
    "button_fg": "#FFFFFF",
    "entry_bg": "#4D4D4D",
    "text_color": "#FFFFFF",
    "success": "#28A745",
    "error": "#DC3545",
    "muted": "#CCCCCC"
}

class SimpleChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("🎯 Network Chat Uygulaması - TCP/UDP & Topology Discovery")
        self.master.geometry("1000x700")
        self.master.configure(bg=THEME["bg"])
        
        # Bağlantı durumları
        self.tcp_server = None
        self.udp_server = None
        self.tcp_server_thread = None
        self.udp_server_thread = None
        
        # Topology discovery
        self.topology_discovery = topology_discovery.topology_discovery
        
        # İstemci modu için
        self.client_socket = None
        self.client_thread = None
        self.is_client_mode = False
        
        # Kullanıcı verileri
        self.current_username = ""
        
        # UI bileşenleri
        self.connection_type = tk.StringVar(value="tcp")
        self.server_port = 12345  # Varsayılan port
        
        self.setup_ui()

    def find_available_port(self, start_port=12345):
        """Uygun port bul"""
        import socket
        for port in range(start_port, start_port + 100):
            try:
                # TCP test
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_sock.bind(('', port))
                tcp_sock.close()
                
                # UDP test
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.bind(('', port))
                udp_sock.close()
                
                return port
            except OSError:
                continue
        
        # Hiç bulamazsa rastgele port kullan
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def setup_ui(self):
        """Ana arayüzü kur"""
        main_frame = tk.Frame(self.master, bg=THEME["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Sol panel - Chat alanı
        self.setup_chat_area(main_frame)
        
        # Sağ panel - Kontrol paneli
        self.setup_control_panel(main_frame)

    def setup_chat_area(self, parent):
        """Chat alanını kur"""
        chat_frame = tk.Frame(parent, bg=THEME["panel_bg"], relief="raised", bd=1)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Başlık
        tk.Label(chat_frame, text="💬 Sohbet Alanı", 
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 14, "bold")).pack(pady=10)
        
        # Chat mesajları
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            bg=THEME["bg"], fg=THEME["text_color"],
            font=("Arial", 11),
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=15
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Mesaj giriş alanı
        msg_frame = tk.Frame(chat_frame, bg=THEME["panel_bg"])
        msg_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.message_entry = tk.Entry(
            msg_frame,
            bg=THEME["entry_bg"], fg=THEME["text_color"],
            font=("Arial", 11)
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        self.send_btn = tk.Button(
            msg_frame, text="Gönder",
            command=self.send_message,
            bg=THEME["button_bg"], fg=THEME["button_fg"],
            font=("Arial", 10)
        )
        self.send_btn.pack(side=tk.RIGHT)

    def setup_control_panel(self, parent):
        """Kontrol panelini kur"""
        control_frame = tk.Frame(parent, bg=THEME["panel_bg"], relief="raised", bd=1)
        control_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        control_frame.config(width=250)
        
        # Başlık
        tk.Label(control_frame, text="⚙️ Kontrol Paneli", 
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 14, "bold")).pack(pady=10)
        
        # Kullanıcı adı girişi
        user_frame = tk.LabelFrame(control_frame, text="Kullanıcı",
                                  bg=THEME["panel_bg"], fg=THEME["text_color"])
        user_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.username_entry = tk.Entry(user_frame,
                                     bg=THEME["entry_bg"], fg=THEME["text_color"])
        self.username_entry.pack(fill=tk.X, padx=5, pady=5)
        
        # Bağlantı türü seçimi
        conn_frame = tk.LabelFrame(control_frame, text="Bağlantı Türü",
                                  bg=THEME["panel_bg"], fg=THEME["text_color"])
        conn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Radiobutton(conn_frame, text="TCP - Güvenli",
                      variable=self.connection_type, value="tcp",
                      bg=THEME["panel_bg"], fg=THEME["text_color"]).pack(anchor="w", padx=5)
        
        tk.Radiobutton(conn_frame, text="UDP - Hızlı",
                      variable=self.connection_type, value="udp",
                      bg=THEME["panel_bg"], fg=THEME["text_color"]).pack(anchor="w", padx=5)
        
        # Port bilgisi ve giriş
        port_sub_frame = tk.Frame(conn_frame, bg=THEME["panel_bg"])
        port_sub_frame.pack(fill=tk.X, padx=5, pady=2)
        
        tk.Label(port_sub_frame, text="Port:",
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 9)).pack(side=tk.LEFT)
        
        self.port_entry = tk.Entry(port_sub_frame, width=8,
                                  bg=THEME["entry_bg"], fg=THEME["text_color"],
                                  font=("Arial", 9))
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))
        self.port_entry.insert(0, str(self.server_port))
        
        self.port_label = tk.Label(port_sub_frame, text=f"(Sunucu: {self.server_port})",
                                  bg=THEME["panel_bg"], fg=THEME["muted"],
                                  font=("Arial", 8))
        self.port_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Sunucu/İstemci kontrolleri
        server_frame = tk.LabelFrame(control_frame, text="Bağlantı",
                                    bg=THEME["panel_bg"], fg=THEME["text_color"])
        server_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Sunucu butonları
        server_sub_frame = tk.Frame(server_frame, bg=THEME["panel_bg"])
        server_sub_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_server_btn = tk.Button(server_sub_frame, text="🚀 Sunucu Başlat",
                                         command=self.start_server,
                                         bg=THEME["success"], fg=THEME["button_fg"])
        self.start_server_btn.pack(fill=tk.X, pady=2)
        
        self.stop_server_btn = tk.Button(server_sub_frame, text="⏹️ Sunucu Durdur",
                                        command=self.stop_server,
                                        bg=THEME["error"], fg=THEME["button_fg"])
        self.stop_server_btn.pack(fill=tk.X, pady=2)
        
        # İstemci butonları
        client_sub_frame = tk.Frame(server_frame, bg=THEME["panel_bg"])
        client_sub_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.connect_btn = tk.Button(client_sub_frame, text="🔗 Sunucuya Bağlan",
                                    command=self.connect_to_server,
                                    bg=THEME["button_bg"], fg=THEME["button_fg"])
        self.connect_btn.pack(fill=tk.X, pady=2)
        
        self.disconnect_btn = tk.Button(client_sub_frame, text="❌ Bağlantıyı Kes",
                                       command=self.disconnect_from_server,
                                       bg=THEME["error"], fg=THEME["button_fg"])
        self.disconnect_btn.pack(fill=tk.X, pady=2)
        
        # Durum gösterimi
        self.status_label = tk.Label(control_frame,
                                    text="🔴 Bağlantı Yok",
                                    bg=THEME["panel_bg"], fg=THEME["error"])
        self.status_label.pack(pady=10)
        
        # Network Topology butonu
        self.topology_btn = tk.Button(control_frame, text="🌐 Network Haritası",
                                     command=self.show_network_topology,
                                     bg=THEME["button_bg"], fg=THEME["button_fg"])
        self.topology_btn.pack(fill=tk.X, padx=10, pady=5)
        
        # Kullanım rehberi
        help_frame = tk.LabelFrame(control_frame, text="💡 Kullanım Rehberi",
                                  bg=THEME["panel_bg"], fg=THEME["text_color"])
        help_frame.pack(fill=tk.X, padx=10, pady=5)
        
        help_text = tk.Text(help_frame, height=8, width=25,
                           bg=THEME["bg"], fg=THEME["muted"],
                           font=("Arial", 9), wrap=tk.WORD)
        help_text.pack(fill=tk.X, padx=5, pady=5)
        
        help_content = """🎯 CHAT UYGULAMASI

✅ HIZLI BAŞLANGIÇ:
1. Pencere 1: "emre" → Sunucu Başlat
2. Pencere 2: "ali" → Sunucuya Bağlan  
3. Mesajlaşın! 🎉

🚀 SUNUCU:
- Kullanıcı adı girin
- TCP seçin (önerilen)
- "Sunucu Başlat" tıklayın

🔗 İSTEMCİ:
- Kullanıcı adı girin  
- Port otomatik güncellenir
- "Sunucuya Bağlan" tıklayın

📡 ÖZELLİKLER:
✓ TCP/UDP protokol desteği
✓ Çoklu kullanıcı 
✓ Network topology haritası
✓ Otomatik port yönetimi

⚡ Etiketler: [Sen] [Diğer] [Sistem]"""

        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)

    def start_server(self):
        """Seçili sunucu türünü başlat"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Hata", "Kullanıcı adı girin!")
            return
        
        if self.tcp_server or self.udp_server:
            messagebox.showwarning("Uyarı", "Zaten bir sunucu çalışıyor!")
            return
        
        self.current_username = username
        conn_type = self.connection_type.get()
        
        # Uygun port bul
        self.server_port = self.find_available_port()
        self.port_label.config(text=f"(Sunucu: {self.server_port})")
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, str(self.server_port))
        
        try:
            if conn_type == "tcp":
                self.start_tcp_server()
            else:
                self.start_udp_server()
        except Exception as e:
            messagebox.showerror("Hata", f"Sunucu başlatılamadı: {e}")
            self.port_label.config(text=f"(Hata: {self.server_port})")

    def stop_server(self):
        """Aktif sunucuyu durdur"""
        try:
            # Sunucu durdur
            if self.tcp_server:
                server.stop_server()
                self.tcp_server = None
                
            if self.udp_server:
                self.udp_server.stop()
                self.udp_server = None
            
            # İstemci bağlantısını kes
            if self.is_client_mode:
                self.disconnect_from_server()
            
            # Topology discovery'yi durdur
            try:
                self.topology_discovery.stop_discovery()
            except:
                pass
            
            # Port'u resetle
            self.server_port = 12345
            self.port_label.config(text=f"(Sunucu: {self.server_port})")
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, str(self.server_port))
                
            self.status_label.config(text="🔴 Bağlantı Yok", fg=THEME["error"])
            self.add_message("[Sistem] Tüm bağlantılar durduruldu")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantılar durdurulamadı: {e}")

    def start_tcp_server(self):
        """TCP sunucuyu başlat"""
        # Custom port ile TCP sunucu başlat
        def start_tcp_with_port():
            import server
            server.start_server_with_port(self.server_port)
        
        self.tcp_server_thread = threading.Thread(target=start_tcp_with_port, daemon=True)
        self.tcp_server_thread.start()
        self.tcp_server = True
        
        # Sunucu mesaj kontrolü thread'i başlat
        self.start_server_message_listener()
        
        # Topology discovery başlat (basitleştirildi)
        try:
            self.topology_discovery.start_discovery(self.current_username)
        except:
            pass  # Topology discovery hatalarını yoksay
        
        self.status_label.config(text=f"🟢 TCP Server:{self.server_port}", fg=THEME["success"])
        self.add_message(f"[Sistem] TCP sunucu başlatıldı - {self.current_username} (Port: {self.server_port})")

    def start_udp_server(self):
        """UDP sunucuyu başlat"""
        self.udp_server = udp_server.UDPServer(port=self.server_port)
        self.udp_server_thread = threading.Thread(target=self.udp_server.start, daemon=True)
        self.udp_server_thread.start()
        
        # Topology discovery başlat (basitleştirildi)
        try:
            self.topology_discovery.start_discovery(self.current_username)
        except:
            pass  # Topology discovery hatalarını yoksay
        
        self.status_label.config(text=f"🟢 UDP Server:{self.server_port}", fg=THEME["success"])
        self.add_message(f"[Sistem] UDP sunucu başlatıldı - {self.current_username} (Port: {self.server_port})")
    
    def start_server_message_listener(self):
        """Sunucu modunda mesaj alma thread'i"""
        def server_message_listener():
            import server
            
            while self.tcp_server or self.udp_server:
                try:
                    # TCP sunucu mesajlarını kontrol et
                    if self.tcp_server:
                        messages = server.get_server_messages()
                        for msg in messages:
                            if msg["sender"] != self.current_username:
                                self.add_message(f"[Diğer] {msg['sender']}: {msg['text']}")
                    
                    time.sleep(0.1)  # 100ms kontrol aralığı
                    
                except Exception as e:
                    break
        
        self.server_listener_thread = threading.Thread(target=server_message_listener, daemon=True)
        self.server_listener_thread.start()
    
    def connect_to_server(self):
        """Mevcut sunucuya istemci olarak bağlan"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Hata", "Kullanıcı adı girin!")
            return
        
        if self.is_client_mode:
            messagebox.showwarning("Uyarı", "Zaten istemci olarak bağlısınız!")
            return
            
        if self.tcp_server or self.udp_server:
            result = messagebox.askyesno("Uyarı", 
                "Sunucu modu aktif! Önce sunucuyu durdurup istemci olmak istiyor musunuz?")
            if result:
                self.stop_server()
            else:
                return
        
        self.current_username = username
        conn_type = self.connection_type.get()
        
        # İstemci port'unu al
        try:
            client_port = int(self.port_entry.get().strip())
            if client_port <= 0 or client_port > 65535:
                raise ValueError("Geçersiz port")
        except ValueError:
            messagebox.showerror("Hata", "Geçerli bir port numarası girin (1-65535)!")
            return
        
        try:
            if conn_type == "tcp":
                self.connect_tcp_client(client_port)
            else:
                self.connect_udp_client(client_port)
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı kurulamadı: {e}\n\nSunucu port {client_port}'ta çalışıyor mu kontrol edin.")
    
    def connect_tcp_client(self, target_port):
        """TCP istemci bağlantısı"""
        import socket
        from protocol import build_packet, parse_packet, MAX_PACKET_SIZE
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(("localhost", target_port))
        
        # JOIN mesajı gönder
        join_packet = build_packet(self.current_username, "join", "katıldı")
        self.client_socket.send(join_packet)
        
        self.is_client_mode = True
        self.status_label.config(text=f"🟢 TCP Client:{target_port}", fg=THEME["success"])
        self.add_message(f"[Sistem] TCP sunucuya bağlanıldı - {self.current_username} (Port: {target_port})")
        
        # Mesaj alma thread'i
        def receive_tcp_messages():
            import socket
            while self.is_client_mode:
                try:
                    data = self.client_socket.recv(MAX_PACKET_SIZE)
                    if not data:
                        self.add_message("[Sistem] Sunucu bağlantısı kesildi")
                        break
                    
                    packet = parse_packet(data)
                    if packet:
                        sender = packet["header"]["sender"]
                        text = packet["payload"]["text"]
                        msg_type = packet["header"]["type"]
                        
                        if msg_type == "message":
                            if sender == "SERVER":
                                self.add_message(f"[Sistem] {text}")
                            elif sender != self.current_username:
                                self.add_message(f"[Diğer] {sender}: {text}")
                        elif msg_type == "userlist":
                            if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
                                users = packet["payload"]["extra"]["users"]
                                user_str = ", ".join(users)
                                self.add_message(f"[Sistem] Bağlı kullanıcılar: {user_str}")
                            else:
                                self.add_message(f"[Sistem] {text}")
                        else:
                            self.add_message(f"[{sender}] {text}")
                    
                except Exception as e:
                    if self.is_client_mode:
                        self.add_message(f"[Hata] Bağlantı kesildi: {e}")
                    break
        
        self.client_thread = threading.Thread(target=receive_tcp_messages, daemon=True)
        self.client_thread.start()
    
    def connect_udp_client(self, target_port):
        """UDP istemci bağlantısı"""
        import socket
        from protocol import build_packet, parse_packet, MAX_PACKET_SIZE
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_addr = ("localhost", target_port)
        
        # JOIN mesajı gönder
        join_packet = build_packet(self.current_username, "join", "katıldı")
        self.client_socket.sendto(join_packet, server_addr)
        
        self.is_client_mode = True
        self.status_label.config(text=f"🟢 UDP Client:{target_port}", fg=THEME["success"])
        self.add_message(f"[Sistem] UDP sunucuya bağlanıldı - {self.current_username} (Port: {target_port})")
        
        # Mesaj alma thread'i
        def receive_udp_messages():
            while self.is_client_mode:
                try:
                    data, addr = self.client_socket.recvfrom(MAX_PACKET_SIZE)
                    packet = parse_packet(data)
                    if packet:
                        sender = packet["header"]["sender"]
                        text = packet["payload"]["text"]
                        msg_type = packet["header"]["type"]
                        
                        # ACK gönder
                        if "seq" in packet["header"]:
                            ack_packet = build_packet("CLIENT", "ack", seq=packet["header"]["seq"])
                            self.client_socket.sendto(ack_packet, server_addr)
                        
                        if msg_type == "message":
                            if sender == "SERVER":
                                self.add_message(f"[Sistem] {text}")
                            elif sender != self.current_username:
                                self.add_message(f"[Diğer] {sender}: {text}")
                        elif msg_type == "userlist":
                            if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
                                users = packet["payload"]["extra"]["users"]
                                user_str = ", ".join(users)
                                self.add_message(f"[Sistem] Bağlı kullanıcılar: {user_str}")
                            else:
                                self.add_message(f"[Sistem] {text}")
                        else:
                            self.add_message(f"[{sender}] {text}")
                            
                except Exception as e:
                    if self.is_client_mode:
                        self.add_message(f"[Hata] Bağlantı kesildi: {e}")
                    break
        
        self.client_thread = threading.Thread(target=receive_udp_messages, daemon=True)
        self.client_thread.start()
    
    def disconnect_from_server(self):
        """Sunucudan bağlantıyı kes"""
        if not self.is_client_mode:
            messagebox.showwarning("Uyarı", "İstemci bağlantısı yok!")
            return
        
        try:
            # LEAVE mesajı gönder
            if self.client_socket:
                from protocol import build_packet
                leave_packet = build_packet(self.current_username, "leave", "ayrıldı")
                
                if self.connection_type.get() == "tcp":
                    self.client_socket.send(leave_packet)
                else:
                    try:
                        target_port = int(self.port_entry.get().strip())
                        self.client_socket.sendto(leave_packet, ("localhost", target_port))
                    except:
                        self.client_socket.sendto(leave_packet, ("localhost", 12345))
                
                self.client_socket.close()
                self.client_socket = None
            
            self.is_client_mode = False
            self.status_label.config(text="🔴 Bağlantı Yok", fg=THEME["error"])
            self.add_message("[Sistem] Sunucu bağlantısı kesildi")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı kesilemedi: {e}")
            self.is_client_mode = False
            self.status_label.config(text="🔴 Bağlantı Yok", fg=THEME["error"])

    def send_message(self, event=None):
        """Mesaj gönder"""
        message = self.message_entry.get().strip()
        if not message:
            return
            
        if not self.current_username:
            messagebox.showerror("Hata", "Önce sunucu başlatın!")
            return
        
        # TCP sunucu varsa TCP olarak gönder
        if self.tcp_server:
            try:
                # TCP sunucudaki tüm istemcilere broadcast yap
                from protocol import build_packet
                import server
                packet = build_packet(self.current_username, "message", message)
                
                # Sunucudan gelen mesajları broadcast et
                server.broadcast(packet)
                
                self.add_message(f"[Sen] {self.current_username}: {message}")
            except Exception as e:
                self.add_message(f"[Hata] Mesaj gönderilemedi: {e}")
        
        # UDP sunucu varsa UDP olarak gönder  
        elif self.udp_server:
            try:
                from protocol import build_packet
                packet = build_packet(self.current_username, "message", message)
                # UDP broadcast
                self.udp_server.broadcast_to_all(packet)
                self.add_message(f"[Sen] {self.current_username}: {message}")
            except Exception as e:
                self.add_message(f"[Hata] Mesaj gönderilemedi: {e}")
        # İstemci modunda mesaj gönder
        elif self.is_client_mode and self.client_socket:
            try:
                from protocol import build_packet
                packet = build_packet(self.current_username, "message", message)
                
                if self.connection_type.get() == "tcp":
                    self.client_socket.send(packet)
                else:
                    # UDP için target port'u al
                    try:
                        target_port = int(self.port_entry.get().strip())
                        self.client_socket.sendto(packet, ("localhost", target_port))
                    except:
                        self.client_socket.sendto(packet, ("localhost", 12345))
                
                # Kendi mesajını göster 
                self.add_message(f"[Sen] {self.current_username}: {message}")
            except Exception as e:
                self.add_message(f"[Hata] Mesaj gönderilemedi: {e}")
        else:
            self.add_message("[Hata] Aktif bağlantı yok!")
            
        self.message_entry.delete(0, tk.END)

    def add_message(self, message: str):
        """Chat'e mesaj ekle"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def show_network_topology(self):
        """Network topology penceresini göster"""
        if not self.current_username:
            messagebox.showwarning("Uyarı", "Önce sunucu başlatın!")
            return
        
        # Topology verilerini al
        topology_data = self.topology_discovery.get_network_topology()
        peer_list = self.topology_discovery.get_peer_list()
        
        # Yeni pencere oluştur
        topology_window = tk.Toplevel(self.master)
        topology_window.title("Network Topology Haritası")
        topology_window.geometry("600x500")
        topology_window.configure(bg=THEME["bg"])
        
        # Başlık
        tk.Label(topology_window, text="🌐 Network Topology Discovery",
                bg=THEME["bg"], fg=THEME["text_color"],
                font=("Arial", 16, "bold")).pack(pady=10)
        
        # Ana frame
        main_frame = tk.Frame(topology_window, bg=THEME["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Sol panel - Peer listesi
        left_frame = tk.LabelFrame(main_frame, text="Aktif Peer'lar",
                                  bg=THEME["panel_bg"], fg=THEME["text_color"])
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        left_frame.config(width=250)
        
        # Peer listesi
        peer_text = scrolledtext.ScrolledText(left_frame, 
                                            bg=THEME["bg"], fg=THEME["text_color"],
                                            font=("Courier", 10), height=15, width=30)
        peer_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sağ panel - Network haritası
        right_frame = tk.LabelFrame(main_frame, text="Network Haritası",
                                   bg=THEME["panel_bg"], fg=THEME["text_color"])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Network haritası
        map_text = scrolledtext.ScrolledText(right_frame,
                                           bg=THEME["bg"], fg=THEME["text_color"],
                                           font=("Courier", 9), height=15)
        map_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alt panel - Bilgiler
        info_frame = tk.Frame(topology_window, bg=THEME["panel_bg"])
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Bilgi etiketleri
        info_text = f"Toplam Peer: {len(peer_list)} | Yerel Peer: {topology_data.get('local_peer', 'N/A')}"
        tk.Label(info_frame, text=info_text,
                bg=THEME["panel_bg"], fg=THEME["text_color"]).pack(side=tk.LEFT)
        
        # Yenile butonu
        refresh_btn = tk.Button(info_frame, text="🔄 Yenile",
                               command=lambda: self.refresh_topology(peer_text, map_text, info_frame),
                               bg=THEME["button_bg"], fg=THEME["button_fg"])
        refresh_btn.pack(side=tk.RIGHT)
        
        # İlk yükleme
        self.refresh_topology_data(peer_text, map_text, peer_list, topology_data)
    
    def refresh_topology(self, peer_text, map_text, info_frame):
        """Topology verilerini yenile"""
        topology_data = self.topology_discovery.get_network_topology()
        peer_list = self.topology_discovery.get_peer_list()
        
        # Info frame güncelle
        for widget in info_frame.winfo_children():
            if isinstance(widget, tk.Label):
                info_text = f"Toplam Peer: {len(peer_list)} | Yerel Peer: {topology_data.get('local_peer', 'N/A')}"
                widget.config(text=info_text)
                break
        
        self.refresh_topology_data(peer_text, map_text, peer_list, topology_data)
    
    def refresh_topology_data(self, peer_text, map_text, peer_list, topology_data):
        """Topology verilerini göster"""
        # Peer listesini göster
        peer_text.config(state=tk.NORMAL)
        peer_text.delete(1.0, tk.END)
        
        peer_text.insert(tk.END, "PEER LİSTESİ\n")
        peer_text.insert(tk.END, "=" * 25 + "\n\n")
        
        if not peer_list:
            peer_text.insert(tk.END, "Henüz peer keşfedilmedi.\n")
        else:
            for peer in peer_list:
                status_icon = "🟢" if peer["status"] == "active" else "🔴"
                rtt_text = f"{peer['rtt']:.1f}ms" if peer['rtt'] > 0 else "N/A"
                
                peer_text.insert(tk.END, f"{status_icon} {peer['peer_id']}\n")
                peer_text.insert(tk.END, f"   IP: {peer['ip']}:{peer['port']}\n")
                peer_text.insert(tk.END, f"   RTT: {rtt_text}\n")
                peer_text.insert(tk.END, f"   Durum: {peer['status']}\n\n")
        
        peer_text.config(state=tk.DISABLED)
        
        # Network haritasını göster  
        map_text.config(state=tk.NORMAL)
        map_text.delete(1.0, tk.END)
        
        map_text.insert(tk.END, "NETWORK HARİTASI\n")
        map_text.insert(tk.END, "=" * 30 + "\n\n")
        
        network_map = topology_data.get("network_map", {})
        local_peer = topology_data.get("local_peer", "")
        
        if not network_map:
            map_text.insert(tk.END, "Network haritası henüz oluşturulmadı.\n")
        else:
            # ASCII art network haritası
            map_text.insert(tk.END, f"📍 {local_peer} (Sen)\n")
            
            if local_peer in network_map:
                connections = network_map[local_peer]
                if connections:
                    map_text.insert(tk.END, "├── Bağlantılar:\n")
                    for peer_id, conn_info in connections.items():
                        rtt = conn_info.get("rtt", 0)
                        rtt_text = f"{rtt:.1f}ms" if rtt > 0 else "N/A"
                        map_text.insert(tk.END, f"│   └── {peer_id} ({rtt_text})\n")
                else:
                    map_text.insert(tk.END, "└── Bağlantı yok\n")
            
            map_text.insert(tk.END, "\n🌐 Tüm Network:\n")
            for peer_id, connections in network_map.items():
                if peer_id != local_peer:
                    map_text.insert(tk.END, f"📍 {peer_id}\n")
                    if connections:
                        for conn_peer, conn_info in connections.items():
                            rtt = conn_info.get("rtt", 0)
                            rtt_text = f"{rtt:.1f}ms" if rtt > 0 else "N/A"
                            map_text.insert(tk.END, f"   └── {conn_peer} ({rtt_text})\n")
                    else:
                        map_text.insert(tk.END, "   └── Bağlantı yok\n")
        
        # Keşif zamanını ekle
        discovery_time = topology_data.get("discovery_time", "N/A")
        map_text.insert(tk.END, f"\n⏰ Son güncelleme: {discovery_time}")
        
        map_text.config(state=tk.DISABLED)

# Ana uygulama
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SimpleChatApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Uygulama başlatma hatası: {e}")
        input("Çıkmak için Enter'a basın...")