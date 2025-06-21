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
import socket

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
    "muted": "#CCCCCC",
    "private": "#FF6B35"
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
        self.connected_users = []  # Bağlı kullanıcılar listesi
        
        # UI bileşenleri
        self.tcp_port = 12345  # TCP public chat port
        self.udp_port = 12346  # UDP private messaging port
        self.server_port = self.tcp_port  # Geriye uyumluluk için
        
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
        
        # Mesaj türü seçimi (Proje Kriteri: TCP Public + UDP Private)
        msg_type_frame = tk.Frame(msg_frame, bg=THEME["panel_bg"])
        msg_type_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.msg_type = tk.StringVar(value="public")
        tk.Radiobutton(msg_type_frame, text="📢 Public Chat (TCP)", 
                      variable=self.msg_type, value="public",
                      bg=THEME["panel_bg"], fg=THEME["text_color"],
                      selectcolor=THEME["success"], activebackground=THEME["panel_bg"],
                      command=self.update_message_mode).pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Radiobutton(msg_type_frame, text="🔒 Private Message (UDP)", 
                      variable=self.msg_type, value="private",
                      bg=THEME["panel_bg"], fg=THEME["text_color"],
                      selectcolor=THEME["private"], activebackground=THEME["panel_bg"],
                      command=self.update_message_mode).pack(side=tk.LEFT)
        
        # Private mesaj hedefi (Proje Kriteri: User list selection)
        self.private_target_frame = tk.Frame(msg_frame, bg=THEME["panel_bg"])
        
        tk.Label(self.private_target_frame, text="🎯 Hedef:", 
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 10)).pack(side=tk.LEFT)
        
        self.target_user_label = tk.Label(self.private_target_frame, text="Seçilmedi", 
                                         bg=THEME["panel_bg"], fg=THEME["private"],
                                         font=("Arial", 10, "bold"))
        self.target_user_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Mesaj giriş
        msg_input_frame = tk.Frame(msg_frame, bg=THEME["panel_bg"])
        msg_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.message_entry = tk.Entry(
            msg_input_frame,
            bg=THEME["entry_bg"], fg=THEME["text_color"],
            font=("Arial", 11)
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        self.send_btn = tk.Button(
            msg_input_frame, text="Gönder",
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
        
        # Port bilgisi
        port_info_frame = tk.LabelFrame(control_frame, text="Port Bilgisi",
                                       bg=THEME["panel_bg"], fg=THEME["text_color"])
        port_info_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Label(port_info_frame, text=f"📢 TCP Public Chat: {self.tcp_port}",
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 10)).pack(anchor="w", padx=5, pady=2)
        
        tk.Label(port_info_frame, text=f"🔒 UDP Private Msg: {self.udp_port}",
                bg=THEME["panel_bg"], fg=THEME["text_color"],
                font=("Arial", 10)).pack(anchor="w", padx=5, pady=2)
        
        # Sunucu/İstemci kontrolleri
        server_frame = tk.LabelFrame(control_frame, text="Bağlantı",
                                    bg=THEME["panel_bg"], fg=THEME["text_color"])
        server_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Ana bağlantı butonu (Proje Kriteri: Otomatik bağlantı)
        main_connect_frame = tk.Frame(server_frame, bg=THEME["panel_bg"])
        main_connect_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.auto_connect_btn = tk.Button(main_connect_frame, text="🚀 Otomatik Bağlan",
                                         command=self.auto_connect,
                                         bg=THEME["success"], fg=THEME["button_fg"],
                                         font=("Arial", 11, "bold"))
        self.auto_connect_btn.pack(fill=tk.X, pady=2)
        
        # Disconnect butonu (sadece bu kalsın)
        self.disconnect_btn = tk.Button(server_frame, text="❌ Bağlantıyı Kes",
                                       command=self.disconnect_from_server,
                                       bg=THEME["error"], fg=THEME["button_fg"],
                                       font=("Arial", 10))
        self.disconnect_btn.pack(fill=tk.X, pady=5, padx=5)
        
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
        
        # Bağlı kullanıcılar listesi
        users_frame = tk.LabelFrame(control_frame, text="👥 Bağlı Kullanıcılar",
                                   bg=THEME["panel_bg"], fg=THEME["text_color"])
        users_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Kullanıcı listesi (Proje Kriteri: User list for private messaging)
        self.users_listbox = tk.Listbox(users_frame, 
                                       bg=THEME["bg"], fg=THEME["text_color"],
                                       font=("Arial", 10), height=8,
                                       selectbackground=THEME["button_bg"])
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.users_listbox.bind("<Double-Button-1>", self.select_user_from_list)
        
        # Kullanıcı listesi kontrolleri
        user_ctrl_frame = tk.Frame(users_frame, bg=THEME["panel_bg"])
        user_ctrl_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        tk.Button(user_ctrl_frame, text="🔄 Yenile",
                 command=self.refresh_user_list,
                 bg=THEME["button_bg"], fg=THEME["button_fg"],
                 font=("Arial", 9)).pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(user_ctrl_frame, text="💬 Private Seç",
                 command=self.select_user_for_private,
                 bg=THEME["private"], fg=THEME["button_fg"],
                 font=("Arial", 9)).pack(side=tk.RIGHT)
        
        # İlk yükleme
        self.refresh_user_list()
        
        # Başlangıçta sunucu kontrolü yap
        threading.Thread(target=self.check_server_on_startup, daemon=True).start()
        
        # Private messaging için
        self.selected_user = None
        self.tcp_client_socket = None
        self.udp_client_socket = None

    def update_message_mode(self):
        """Mesaj moduna göre UI güncelle"""
        if self.msg_type.get() == "private":
            self.private_target_frame.pack(fill=tk.X, pady=(0, 5))
        else:
            self.private_target_frame.pack_forget()

    def select_user_for_private(self, event=None):
        """Private mesaj için kullanıcı seç (butondan)"""
        try:
            # Mevcut seçimi al
            selection = self.users_listbox.curselection()
            if selection:
                # Seçili varsa onu kullan
                self.select_user_from_list()
            else:
                # Seçili yoksa ilk uygun kullanıcıyı seç
                if self.connected_users and len(self.connected_users) > 1:
                    other_users = [u for u in self.connected_users if u != self.current_username]
                    if other_users:
                        selected_text = other_users[0]
                        self.selected_user = selected_text
                        self.target_user_label.config(text=selected_text)
                        self.msg_type.set("private")
                        self.update_message_mode()
                        self.add_message(f"[Sistem] 🎯 Private mesaj hedefi: {selected_text}")
                    else:
                        messagebox.showinfo("Bilgi", "Private mesaj için başka kullanıcı bulunamadı.")
                else:
                    messagebox.showinfo("Bilgi", "Private mesaj için başka kullanıcı bulunamadı.")
        except Exception as e:
            self.add_message(f"[Hata] Kullanıcı seçiminde hata: {e}")

    def select_user_from_list(self, event=None):
        """Listbox'dan kullanıcı seç (çift tıklama)"""
        try:
            selection = self.users_listbox.curselection()
            if not selection:
                return
            
            selected_line = self.users_listbox.get(selection[0])
            
            # Format: "👤 username (Sen)" veya "👥 username" veya "🔍 Başka kullanıcı yok"
            if "🔍" in selected_line or "Henüz bağlantı yok" in selected_line:
                messagebox.showinfo("Bilgi", "Geçerli bir kullanıcı seçin!")
                return
            
            # Username'i extract et
            if " (Sen)" in selected_line:
                messagebox.showwarning("Uyarı", "Kendinizi seçemezsiniz!")
                return
            
            # "👥 username" formatından username'i al
            if "👥" in selected_line:
                username = selected_line.replace("👥 ", "").strip()
            elif "👤" in selected_line:
                username = selected_line.replace("👤 ", "").replace(" (Sen)", "").strip()
            else:
                username = selected_line.strip()
            
            if username and username != self.current_username:
                self.selected_user = username
                self.target_user_label.config(text=username)
                self.msg_type.set("private")
                self.update_message_mode()
                self.add_message(f"[Sistem] 🎯 Private mesaj hedefi: {username}")
            else:
                messagebox.showwarning("Uyarı", "Geçerli bir kullanıcı seçin!")
            
        except Exception as e:
            self.add_message(f"[Hata] Kullanıcı seçiminde hata: {e}")

    def check_server_on_startup(self):
        """Başlangıçta sunucu var mı kontrol et"""
        time.sleep(1)  # GUI yüklensin
        
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.connect(("localhost", self.server_port))
            test_sock.close()
            # Sunucu var
            self.add_message("[Sistem] 🔍 Mevcut sunucu bulundu. 'Otomatik Bağlan' ile istemci olabilirsiniz.")
        except:
            # Sunucu yok
            self.add_message("[Sistem] 🚀 Sunucu bulunamadı. 'Otomatik Bağlan' ile ilk kullanıcı olarak sunucu başlatabilirsiniz.")

    def auto_connect(self):
        """Otomatik bağlantı - Proje Kriteri: İlk kullanıcı sunucu, diğerleri istemci"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Hata", "Önce kullanıcı adı girin!")
            return
        
        self.current_username = username
        
        # Sunucu var mı kontrol et
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.connect(("localhost", self.server_port))
            test_sock.close()
            # Sunucu var, istemci ol
            self.add_message("[Sistem] 🔗 Mevcut sunucuya istemci olarak bağlanılıyor...")
            self.connect_as_client()
        except:
            # Sunucu yok, sunucu ol
            self.add_message("[Sistem] 🚀 İlk kullanıcı olarak sunucu başlatılıyor...")
            self.start_as_server()

    def start_as_server(self):
        """Sunucu olarak başla"""
        try:
            # TCP ve UDP sunucuları başlat
            self.tcp_server_thread = threading.Thread(target=self._start_tcp_server, daemon=True)
            self.tcp_server_thread.start()
            
            self.udp_server = udp_server.UDPServer(port=self.udp_port)
            self.udp_server_thread = threading.Thread(target=self.udp_server.start, daemon=True)
            self.udp_server_thread.start()
            
            # Sunucu modunda da UDP client socket oluştur (private mesaj için)
            self.udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Sunucu kendini UDP'ye de register etsin
            time.sleep(0.5)  # UDP server'ın başlamasını bekle
            from protocol import build_packet
            udp_join_packet = build_packet(self.current_username, "join", "katıldı")
            self.udp_client_socket.sendto(udp_join_packet, ("localhost", self.udp_port))
            
            self.tcp_server = True
            self.status_label.config(text="🟢 Sunucu Modu (TCP+UDP)", fg=THEME["success"])
            self.connected_users = [self.current_username]
            self.refresh_user_list()
            self.add_message(f"[Sistem] ✅ Sunucu başlatıldı - {self.current_username}")
            self.add_message("[Sistem] 📢 TCP public chat: Port 12345")
            self.add_message("[Sistem] 🔒 UDP private messaging: Port 12346")
            
            # Sunucu mesaj dinleyicisini başlat
            threading.Thread(target=self.server_message_listener, daemon=True).start()
            
            # UDP private mesaj dinleyicisi (sunucu modu için)
            threading.Thread(target=self.udp_private_listener, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sunucu başlatılamadı: {e}")

    def _start_tcp_server(self):
        """TCP sunucu thread fonksiyonu"""
        # Sunucu kullanıcı adını set et
        server.set_server_username(self.current_username)
        server.start_server_with_port(self.server_port)

    def connect_as_client(self):
        """İstemci olarak bağlan"""
        try:
            # TCP bağlantısı
            self.tcp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client_socket.connect(("localhost", self.server_port))
            
            # UDP socket
            self.udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # JOIN mesajları gönder
            from protocol import build_packet
            
            # TCP JOIN
            tcp_join_packet = build_packet(self.current_username, "join", "katıldı")
            self.tcp_client_socket.send(tcp_join_packet)
            
            # UDP JOIN (private messaging için gerekli)
            udp_join_packet = build_packet(self.current_username, "join", "katıldı")
            self.udp_client_socket.sendto(udp_join_packet, ("localhost", self.udp_port))
            
            self.is_client_mode = True
            self.status_label.config(text="🟢 İstemci Modu (TCP+UDP)", fg=THEME["success"])
            self.add_message(f"[Sistem] ✅ Sunucuya bağlanıldı - {self.current_username}")
            self.add_message("[Sistem] ✅ TCP ve UDP bağlantıları kuruldu")
            
            # Mesaj alma thread'i
            threading.Thread(target=self.client_message_listener, daemon=True).start()
            
            # UDP private mesaj dinleyicisi
            threading.Thread(target=self.udp_private_listener, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sunucuya bağlanılamadı: {e}")

    def server_message_listener(self):
        """Sunucu modu mesaj dinleyicisi"""
        while self.tcp_server:
            try:
                messages = server.get_server_messages()
                for msg in messages:
                    if msg["type"] == "message" and msg["sender"] != self.current_username:
                        self.add_message(f"[Public] {msg['sender']}: {msg['text']}")
                    elif msg["type"] == "userlist":
                        # Server'ın kullanıcı listesi güncellemesi
                        connected_users = msg["users"]
                        all_users = [self.current_username] + connected_users
                        self.update_user_list(all_users)
                        if connected_users:
                            self.add_message(f"[Sistem] Yeni kullanıcı listesi: {', '.join(all_users)}")
                time.sleep(0.1)
            except:
                break

    def client_message_listener(self):
        """İstemci modu mesaj dinleyicisi"""
        from protocol import parse_packet, MAX_PACKET_SIZE
        
        while self.is_client_mode:
            try:
                data = self.tcp_client_socket.recv(MAX_PACKET_SIZE)
                if not data:
                    self.add_message("[Sistem] ❌ Sunucu bağlantısı kesildi")
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
                            self.add_message(f"[Public] {sender}: {text}")
                    elif msg_type == "userlist":
                        if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
                            # TCP server artık tüm kullanıcıları gönderiyor (sunucu dahil)
                            all_users = packet["payload"]["extra"]["users"]
                            
                            # Kendimizi de eklememiz gerekirse ekle
                            if self.current_username not in all_users:
                                all_users.append(self.current_username)
                            
                            self.update_user_list(all_users)
                            self.add_message(f"[Sistem] Kullanıcı listesi güncellendi: {', '.join(all_users)}")
            except:
                if self.is_client_mode:
                    self.add_message("[Sistem] ❌ Bağlantı hatası")
                break


    
    def disconnect_from_server(self):
        """Sunucudan bağlantıyı kes"""
        try:
            from protocol import build_packet
            
            # LEAVE mesajları gönder
            if self.tcp_client_socket:
                tcp_leave_packet = build_packet(self.current_username, "leave", "ayrıldı")
                self.tcp_client_socket.send(tcp_leave_packet)
                self.tcp_client_socket.close()
                self.tcp_client_socket = None
            
            # UDP'den de ayrıl
            if self.udp_client_socket and self.current_username:
                udp_leave_packet = build_packet(self.current_username, "leave", "ayrıldı")
                self.udp_client_socket.sendto(udp_leave_packet, ("localhost", self.udp_port))
                self.udp_client_socket.close()
                self.udp_client_socket = None
            
            # Server sockets'ı kapat
            if self.tcp_server:
                server.stop_server()
                self.tcp_server = None
                
            if self.udp_server:
                self.udp_server.stop()
                self.udp_server = None
            
            self.is_client_mode = False
            self.status_label.config(text="🔴 Bağlantı Yok", fg=THEME["error"])
            self.connected_users = []
            self.selected_user = None
            self.target_user_label.config(text="Seçilmedi")
            self.refresh_user_list()
            self.add_message("[Sistem] Bağlantı kesildi")
            
        except Exception as e:
            self.add_message(f"[Hata] Bağlantı kesme hatası: {e}")
            self.is_client_mode = False
            self.status_label.config(text="🔴 Bağlantı Yok", fg=THEME["error"])
            self.connected_users = []
            self.refresh_user_list()

    def send_message(self, event=None):
        """Mesaj gönder - Proje Kriteri: TCP Public + UDP Private"""
        message = self.message_entry.get().strip()
        if not message:
            return
            
        if not self.current_username:
            messagebox.showerror("Hata", "Önce bağlantı kurun!")
            return
        
        msg_type = self.msg_type.get()
        
        if msg_type == "public":
            self.send_public_message(message)
        else:
            self.send_private_message(message)
            
        self.message_entry.delete(0, tk.END)

    def send_public_message(self, message):
        """Public mesaj gönder (TCP)"""
        try:
            from protocol import build_packet
            
            if self.tcp_server:
                # Sunucu modunda TCP broadcast
                packet = build_packet(self.current_username, "message", message)
                server.broadcast(packet)
                self.add_message(f"[Public] {self.current_username}: {message}")
                
            elif self.is_client_mode and self.tcp_client_socket:
                # İstemci modunda TCP sunucuya gönder
                packet = build_packet(self.current_username, "message", message)
                self.tcp_client_socket.send(packet)
                self.add_message(f"[Public] {self.current_username}: {message}")
            else:
                self.add_message("[Hata] TCP bağlantısı yok!")
                
        except Exception as e:
            self.add_message(f"[Hata] Public mesaj gönderilemedi: {e}")

    def send_private_message(self, message):
        """Private mesaj gönder (UDP)"""
        if not self.selected_user:
            messagebox.showwarning("Uyarı", "Private mesaj için önce kullanıcı seçin!")
            return
        
        if self.selected_user == self.current_username:
            messagebox.showwarning("Uyarı", "Kendinize mesaj gönderemezsiniz!")
            return
        
        try:
            from protocol import build_packet
            
            # UDP private message formatı: @target: message
            packet = build_packet(self.current_username, "private_message", 
                                f"@{self.selected_user}: {message}")
            
            if self.udp_client_socket:
                # Hem sunucu hem istemci modunda UDP ile gönder
                self.udp_client_socket.sendto(packet, ("localhost", self.udp_port))
                self.add_message(f"[Private] {self.current_username} -> {self.selected_user}: {message}")
            else:
                self.add_message("[Hata] UDP bağlantısı yok!")
            
        except Exception as e:
            self.add_message(f"[Hata] Private mesaj gönderilemedi: {e}")

    def udp_private_listener(self):
        """UDP private mesaj dinleyicisi"""
        from protocol import parse_packet, build_packet
        
        while self.is_client_mode or self.tcp_server:
            try:
                if self.udp_client_socket:
                    self.udp_client_socket.settimeout(3)  # 3 saniye timeout
                    data, addr = self.udp_client_socket.recvfrom(1024)
                    
                    packet = parse_packet(data)
                    if packet:
                        sender = packet["header"]["sender"]
                        text = packet["payload"]["text"]
                        msg_type = packet["header"]["type"]
                        seq = packet["header"].get("seq")
                        
                        # ACK gönder (tekrar gönderimi önlemek için)
                        if seq is not None:
                            ack_packet = build_packet("CLIENT", "ack", seq=seq)
                            self.udp_client_socket.sendto(ack_packet, addr)
                        
                        if msg_type == "private_message" and sender != self.current_username:
                            # Private mesaj formatı: [Private from sender] message
                            if text.startswith("[Private from"):
                                # UDP server'dan gelen private mesaj
                                self.add_message(f"[Private] {text}")
                            else:
                                self.add_message(f"[Private] {sender}: {text}")
                        elif msg_type == "message" and sender == "SERVER":
                            # UDP server'dan gelen confirmation/error mesajları
                            self.add_message(f"[Sistem] {text}")
                            
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_client_mode or self.tcp_server:
                    # Sadece gerçek hata ise log et
                    pass
                break

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
    
    def refresh_user_list(self):
        """Bağlı kullanıcılar listesini güncelle"""
        # TCP sunucu ise direkt server'dan al
        if self.tcp_server:
            try:
                import server
                connected_users = server.get_connected_users()
                # Sunucu kullanıcı adını da ekle
                all_users = [self.current_username] + connected_users
                self.connected_users = all_users
            except:
                self.connected_users = [self.current_username] if self.current_username else []
        
        # Listbox'u güncelle
        self.users_listbox.delete(0, tk.END)
        
        if not self.current_username:
            self.users_listbox.insert(tk.END, "🔴 Henüz bağlantı yok")
        else:
            # Kullanıcıları listbox'a ekle
            for user in self.connected_users:
                if user == self.current_username:
                    self.users_listbox.insert(tk.END, f"👤 {user} (Sen)")
                else:
                    self.users_listbox.insert(tk.END, f"👥 {user}")
            
            if len(self.connected_users) <= 1:
                self.users_listbox.insert(tk.END, "🔍 Başka kullanıcı yok")
    
    def update_user_list(self, users):
        """Kullanıcı listesini güncelle (sunucudan gelen verilerle)"""
        self.connected_users = users
        self.refresh_user_list()

# Ana uygulama
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = SimpleChatApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Uygulama başlatma hatası: {e}")
        input("Çıkmak için Enter'a basın...")