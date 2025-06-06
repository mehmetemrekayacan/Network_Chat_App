"""
Modern arayüzlü chat uygulaması (Tkinter GUI).
- Merkezi bağlantı kontrolü (TCP, UDP ve P2P)
- Ağ topolojisi görselleştirme
- Gerçek zamanlı ağ durumu izleme
- Gelişmiş RTT ölçümü
- Tema desteği (açık/koyu mod)
- Ağ istatistikleri paneli
- Mesaj geçmişi yönetimi
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import os
from typing import Optional, Dict, Any, List
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
matplotlib.use('TkAgg')  # Tkinter backend kullan

# Sunucu modüllerini import et
import server
import udp_server
from p2p_node import P2PNode

# Tema renkleri - Açık Mod
LIGHT_THEME = {
    "bg": "#FFFFFF",
    "panel_bg": "#F5F5F5",
    "button_bg": "#007ACC",
    "button_fg": "#FFFFFF",
    "entry_bg": "#FFFFFF",
    "text_color": "#000000",
    "secondary": "#005A9E",
    "primary": "#007ACC",
    "success": "#28A745",
    "error": "#DC3545",
    "warning": "#FFC107",
    "muted": "#6C757D",
    "border": "#DEE2E6"
}

# Tema renkleri - Koyu Mod
DARK_THEME = {
    "bg": "#2B2B2B",
    "panel_bg": "#3C3C3C",
    "button_bg": "#007ACC",
    "button_fg": "#FFFFFF",
    "entry_bg": "#4D4D4D",
    "text_color": "#FFFFFF",
    "secondary": "#005A9E",
    "primary": "#007ACC",
    "success": "#28A745",
    "error": "#DC3545",
    "warning": "#FFC107",
    "muted": "#CCCCCC",
    "border": "#495057"
}

# Varsayılan tema
current_theme = DARK_THEME

# Modern tema renkleri (backward compatibility)
DARK_BG = current_theme["bg"]
PANEL_BG = current_theme["panel_bg"]
BUTTON_BG = current_theme["button_bg"]
BUTTON_FG = current_theme["button_fg"]
ENTRY_BG = current_theme["entry_bg"]
TEXT_COLOR = current_theme["text_color"]
SECONDARY = current_theme["secondary"]
PRIMARY = current_theme["primary"]
SUCCESS_COLOR = current_theme["success"]
ERROR_COLOR = current_theme["error"]
WARNING_COLOR = current_theme["warning"]

class ModernChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Modern Chat Uygulaması v3.0")
        self.master.geometry("1200x800")
        self.master.configure(bg=DARK_BG)
        self.master.minsize(1000, 600)  # Minimum boyut
        
        # Tema yönetimi
        self.current_theme = DARK_THEME
        self.is_dark_mode = True
        
        # Bağlantı durumları
        self.tcp_server = None
        self.udp_server = None
        self.p2p_node = None
        
        # Thread'ler
        self.tcp_server_thread = None
        self.udp_server_thread = None
        
        # Kullanıcı verileri
        self.current_username = ""
        self.connected_users = {}
        
        # Ağ haritası penceresi
        self.network_window = None
        self.stats_window = None
        
        # UI bileşenleri
        self.connection_type = tk.StringVar(value="p2p")
        
        # Mesaj geçmişi
        self.message_history: List[Dict[str, Any]] = []
        self.load_message_history()
        
        # Ağ istatistikleri
        self.network_stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connection_uptime": 0,
            "last_ping": 0,
            "packet_loss": 0,
            "connection_start_time": None
        }
        
        # Bağlantı durumu güncelleme
        self.connection_status = {
            "tcp": "disconnected",
            "udp": "disconnected", 
            "p2p": "disconnected"
        }
        
        self.setup_ui()
        self.start_stats_updater()

    def setup_ui(self):
        """Ana arayüzü kur"""
        # Menü çubuğu
        self.setup_menu_bar()
        
        # Ana çerçeve
        main_frame = tk.Frame(self.master, bg=self.current_theme["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Sol panel - Chat alanı
        self.setup_chat_area(main_frame)
        
        # Orta panel - Kontrol paneli
        self.setup_control_panel(main_frame)
        
        # Sağ panel - Kullanıcılar
        self.setup_users_panel(main_frame)
        
        # Alt panel - Durum çubuğu
        self.setup_status_bar()

    def setup_chat_area(self, parent):
        """Chat alanını kur"""
        chat_frame = tk.Frame(parent, bg=self.current_theme["panel_bg"], relief="raised", bd=1)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        chat_frame.config(width=500)  # Minimum genişlik
        
        # Başlık ve araç çubuğu
        header_frame = tk.Frame(chat_frame, bg=self.current_theme["panel_bg"])
        header_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(header_frame, text="💬 Sohbet Alanı", 
                bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
        
        # Chat araç butonları
        tools_frame = tk.Frame(header_frame, bg=self.current_theme["panel_bg"])
        tools_frame.pack(side=tk.RIGHT)
        
        history_btn = tk.Button(tools_frame, text="📜",
                               command=self.show_message_history,
                               bg=self.current_theme["secondary"],
                               fg=self.current_theme["button_fg"],
                               font=("Segoe UI", 10),
                               width=3, relief="flat")
        history_btn.pack(side=tk.LEFT, padx=2)
        
        clear_btn = tk.Button(tools_frame, text="🧹",
                            command=self.clear_current_chat,
                            bg=self.current_theme["warning"],
                            fg="black",
                            font=("Segoe UI", 10),
                            width=3, relief="flat")
        clear_btn.pack(side=tk.LEFT, padx=2)
        
        # Chat mesajları
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            bg=self.current_theme["bg"], fg=self.current_theme["text_color"],
            font=("Segoe UI", 11),
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=15
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Mesaj giriş alanı
        msg_frame = tk.Frame(chat_frame, bg=self.current_theme["panel_bg"])
        msg_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.message_entry = tk.Entry(
            msg_frame,
            bg=self.current_theme["entry_bg"], fg=self.current_theme["text_color"],
            font=("Segoe UI", 11),
            relief="flat",
            insertbackground=self.current_theme["text_color"]
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        self.send_btn = tk.Button(
            msg_frame, text="📤 Gönder",
            command=self.send_message,
            bg=self.current_theme["button_bg"], fg=self.current_theme["button_fg"],
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        )
        self.send_btn.pack(side=tk.RIGHT)
        
        # Sistem mesajları
        system_header = tk.Frame(chat_frame, bg=self.current_theme["panel_bg"])
        system_header.pack(fill=tk.X, pady=(10, 5))
        
        tk.Label(system_header, text="🔧 Sistem Mesajları", 
                bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
        
        tk.Button(system_header, text="🧹",
                 command=self.clear_system_messages,
                 bg=self.current_theme["muted"],
                 fg=self.current_theme["button_fg"],
                 font=("Segoe UI", 8),
                 width=3, relief="flat").pack(side=tk.RIGHT)
        
        self.system_display = scrolledtext.ScrolledText(
            chat_frame,
            bg=self.current_theme["bg"], fg=self.current_theme["warning"],
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=8
        )
        self.system_display.pack(fill=tk.X, padx=10, pady=(0, 10))

    def setup_control_panel(self, parent):
        """Merkezi kontrol panelini kur"""
        control_frame = tk.Frame(parent, bg=self.current_theme["panel_bg"], relief="raised", bd=1)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, anchor="n")
        control_frame.config(width=300)  # Sabit genişlik
        
        # Başlık
        tk.Label(control_frame, text="⚙️ Bağlantı Kontrolü", 
                bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Kullanıcı adı girişi
        user_frame = tk.LabelFrame(control_frame, text="👤 Kullanıcı Bilgileri",
                                  bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                                  font=("Segoe UI", 11, "bold"))
        user_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Label(user_frame, text="Kullanıcı Adı:",
                bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                font=("Segoe UI", 10)).pack(anchor="w", padx=5, pady=(5, 0))
        
        self.username_entry = tk.Entry(user_frame, width=25,
                                     font=("Segoe UI", 11),
                                     bg=self.current_theme["entry_bg"], fg=self.current_theme["text_color"],
                                     relief="flat",
                                     insertbackground=self.current_theme["text_color"])
        self.username_entry.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # Bağlantı türü seçimi
        conn_frame = tk.LabelFrame(control_frame, text="🌐 Bağlantı Türü",
                                  bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                                  font=("Segoe UI", 11, "bold"))
        conn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Bağlantı türü seçenekleri
        connection_options = [
            ("tcp", "TCP - Güvenli, sıralı iletişim"),
            ("udp", "UDP - Hızlı, düşük gecikme"),
            ("p2p", "P2P - Doğrudan düğüm iletişimi")
        ]
        
        for value, text in connection_options:
            tk.Radiobutton(conn_frame, text=text,
                          variable=self.connection_type,
                          value=value,
                          bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                          selectcolor=self.current_theme["panel_bg"],
                          activebackground=self.current_theme["panel_bg"],
                          activeforeground=self.current_theme["text_color"],
                          font=("Segoe UI", 10)).pack(anchor="w", padx=5, pady=2)
        
        # Sunucu kontrolleri
        server_frame = tk.LabelFrame(control_frame, text="🖥️ Sunucu Kontrolü",
                                    bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                                    font=("Segoe UI", 11, "bold"))
        server_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Durum göstergeleri
        status_frame = tk.Frame(server_frame, bg=self.current_theme["panel_bg"])
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Durum göstergesi fonksiyonu
        def create_status_indicator(parent, text):
            frame = tk.Frame(parent, bg=self.current_theme["panel_bg"])
            frame.pack(fill=tk.X, pady=2)
            
            indicator = tk.Canvas(frame, width=15, height=15, bg=self.current_theme["panel_bg"], highlightthickness=0)
            indicator.pack(side=tk.LEFT, padx=(0, 5))
            indicator.create_oval(3, 3, 12, 12, fill=self.current_theme["error"], outline=self.current_theme["border"])
            
            label = tk.Label(frame, text=text,
                           bg=self.current_theme["panel_bg"], fg=self.current_theme["error"],
                           font=("Segoe UI", 10))
            label.pack(side=tk.LEFT)
            
            return indicator, label
        
        self.tcp_indicator, self.tcp_status_label = create_status_indicator(status_frame, "TCP: 🔴 Kapalı")
        self.udp_indicator, self.udp_status_label = create_status_indicator(status_frame, "UDP: 🔴 Kapalı")
        self.p2p_indicator, self.p2p_status_label = create_status_indicator(status_frame, "P2P: 🔴 Kapalı")
        
        # Kontrol butonları
        button_frame = tk.Frame(server_frame, bg=self.current_theme["panel_bg"])
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_btn = tk.Button(button_frame, text="🚀 Başlat",
                                  command=self.start_connection,
                                  bg=self.current_theme["success"], fg=self.current_theme["button_fg"],
                                  font=("Segoe UI", 11, "bold"),
                                  relief="flat", width=12)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = tk.Button(button_frame, text="⏹️ Durdur",
                                 command=self.stop_connection,
                                 bg=self.current_theme["error"], fg=self.current_theme["button_fg"],
                                 font=("Segoe UI", 11, "bold"),
                                 relief="flat", width=12)
        self.stop_btn.pack(side=tk.LEFT)
        
        # İstemci bağlantısı
        client_frame = tk.LabelFrame(control_frame, text="🔗 Bağlantı Kur",
                                    bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                                    font=("Segoe UI", 11, "bold"))
        client_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Host ve Port
        addr_frame = tk.Frame(client_frame, bg=self.current_theme["panel_bg"])
        addr_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(addr_frame, text="Host:", bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"], font=("Segoe UI", 10)).pack(side=tk.LEFT)
        self.host_entry = tk.Entry(addr_frame, width=12, bg=self.current_theme["entry_bg"], fg=self.current_theme["text_color"], font=("Segoe UI", 10), relief="flat")
        self.host_entry.pack(side=tk.LEFT, padx=5)
        self.host_entry.insert(0, "localhost")
        
        tk.Label(addr_frame, text="Port:", bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"], font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(10, 0))
        self.port_entry = tk.Entry(addr_frame, width=8, bg=self.current_theme["entry_bg"], fg=self.current_theme["text_color"], font=("Segoe UI", 10), relief="flat")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "12345")
        
        # Bağlan butonu
        self.connect_btn = tk.Button(client_frame, text="🔗 Bağlan",
                                    command=self.connect_to_server,
                                    bg=self.current_theme["button_bg"], fg=self.current_theme["button_fg"],
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat")
        self.connect_btn.pack(pady=(5, 2))
        
        # P2P için ek bilgi
        p2p_info = tk.Label(client_frame, 
                           text="💡 P2P için birden fazla farklı porta bağlanabilirsiniz",
                           bg=self.current_theme["panel_bg"], fg=self.current_theme["muted"],
                           font=("Segoe UI", 8),
                           wraplength=200)
        p2p_info.pack(pady=(0, 5))
        
        # Ağ araçları
        tools_frame = tk.LabelFrame(control_frame, text="🛠️ Ağ Araçları",
                                   bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                                   font=("Segoe UI", 11, "bold"))
        tools_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.network_map_btn = tk.Button(tools_frame, text="🗺️ Ağ Haritası",
                                        command=self.show_network_map,
                                        bg=self.current_theme["secondary"], fg=self.current_theme["button_fg"],
                                        font=("Segoe UI", 10, "bold"),
                                        relief="flat")
        self.network_map_btn.pack(fill=tk.X, padx=5, pady=(5, 2))
        
        # Yardım butonu
        help_btn = tk.Button(tools_frame, text="❓ P2P Nasıl Kullanılır?",
                            command=self.show_p2p_help,
                            bg=self.current_theme["warning"], fg="black",
                            font=("Segoe UI", 9, "bold"),
                            relief="flat")
        help_btn.pack(fill=tk.X, padx=5, pady=(2, 5))

    def setup_users_panel(self, parent):
        """Kullanıcılar panelini kur"""
        users_frame = tk.Frame(parent, bg=self.current_theme["panel_bg"], relief="raised", bd=1)
        users_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0), anchor="n")
        users_frame.config(width=300)  # Sabit genişlik
        
        # Başlık
        tk.Label(users_frame, text="👥 Bağlı Kullanıcılar", 
                bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Kullanıcı sayısı
        self.user_count_label = tk.Label(users_frame, text="Toplam: 0 kullanıcı",
                                        bg=self.current_theme["panel_bg"], fg=self.current_theme["muted"],
                                        font=("Segoe UI", 10))
        self.user_count_label.pack(pady=(0, 10))
        
        # Kullanıcı listesi
        listbox_frame = tk.Frame(users_frame, bg=self.current_theme["panel_bg"])
        listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Treeview kullanıcı listesi için
        columns = ("username", "status", "connection")
        self.user_tree = ttk.Treeview(listbox_frame, columns=columns, show="headings", height=15)
        
        # Sütun başlıkları
        self.user_tree.heading("username", text="Kullanıcı")
        self.user_tree.heading("status", text="Durum")
        self.user_tree.heading("connection", text="Bağlantı")
        
        # Sütun genişlikleri
        self.user_tree.column("username", width=120)
        self.user_tree.column("status", width=80)
        self.user_tree.column("connection", width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scrollbar.set)
        
        self.user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Kullanıcı detayları
        detail_frame = tk.LabelFrame(users_frame, text="📊 Kullanıcı Detayları",
                                    bg=self.current_theme["panel_bg"], fg=self.current_theme["text_color"],
                                    font=("Segoe UI", 11, "bold"))
        detail_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.user_detail_text = tk.Text(detail_frame, 
                                       bg=self.current_theme["bg"], fg=self.current_theme["text_color"],
                                       font=("Segoe UI", 10),
                                       height=6, width=30,
                                       state=tk.DISABLED)
        self.user_detail_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Treeview seçim olayı
        self.user_tree.bind("<<TreeviewSelect>>", self.on_user_select)

    def start_connection(self):
        """Seçili bağlantı türünü başlat"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Hata", "Lütfen kullanıcı adı girin!")
            return
        
        # Aktif bağlantı var mı kontrol et
        if self.tcp_server or self.udp_server or self.p2p_node:
            messagebox.showwarning("Uyarı", "Zaten bir bağlantı türü aktif!\n\nÖnce 'Durdur' butonuna basıp mevcut bağlantıyı kapatın.")
            return
        
        self.current_username = username
        conn_type = self.connection_type.get()
        
        try:
            if conn_type == "tcp":
                self.start_tcp_server()
            elif conn_type == "udp":
                self.start_udp_server()
            else:  # P2P
                self.start_p2p_node()
                
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı başlatılamadı: {e}")

    def stop_connection(self):
        """Aktif bağlantıları durdur"""
        try:
            if self.tcp_server:
                server.stop_server()
                self.tcp_server = None
                self.connection_status["tcp"] = "disconnected"
                self.update_tcp_status(False)
                self.add_system_message("🛑 TCP sunucu durduruldu")
                
            if self.udp_server:
                self.udp_server.stop()
                self.udp_server = None
                self.connection_status["udp"] = "disconnected"
                self.update_udp_status(False)
                self.add_system_message("🛑 UDP sunucu durduruldu")
                
            if self.p2p_node:
                self.p2p_node.stop()
                self.p2p_node = None
                self.connection_status["p2p"] = "disconnected"
                self.update_p2p_status(False)
                self.update_user_list()  # Kullanıcı listesini temizle
                self.add_system_message("🛑 P2P düğümü durduruldu")
                
            # Bağlantı süresini sıfırla
            if all(status == "disconnected" for status in self.connection_status.values()):
                self.network_stats["connection_start_time"] = None
                
            self.add_system_message("✅ Tüm bağlantılar güvenli şekilde durduruldu")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı durdurulamadı: {e}")

    def start_tcp_server(self):
        """TCP sunucuyu başlat"""
        try:
            # TCP sunucuyu ayrı thread'de başlat
            self.tcp_server_thread = threading.Thread(target=server.start_server, daemon=True)
            self.tcp_server_thread.start()
            self.tcp_server = True  # Sunucu çalışıyor bayrağı
            self.connection_status["tcp"] = "connected"
            self.network_stats["connection_start_time"] = time.time()
            self.update_tcp_status(True)
            self.add_system_message(f"✅ TCP sunucu başlatıldı - Kullanıcı: {self.current_username}")
            self.add_system_message("📡 TCP sunucu localhost:12345 adresinde dinliyor")
        except Exception as e:
            self.connection_status["tcp"] = "disconnected"
            raise Exception(f"TCP başlatılamadı: {e}")

    def start_udp_server(self):
        """UDP sunucuyu başlat"""
        try:
            # UDP sunucuyu başlat
            self.udp_server = udp_server.UDPServer()
            self.udp_server_thread = threading.Thread(target=self.udp_server.start, daemon=True)
            self.udp_server_thread.start()
            self.connection_status["udp"] = "connected"
            self.network_stats["connection_start_time"] = time.time()
            self.update_udp_status(True)
            self.add_system_message(f"✅ UDP sunucu başlatıldı - Kullanıcı: {self.current_username}")
            self.add_system_message("📡 UDP sunucu localhost:12345 adresinde dinliyor")
        except Exception as e:
            self.connection_status["udp"] = "disconnected"
            raise Exception(f"UDP başlatılamadı: {e}")

    def start_p2p_node(self):
        """P2P düğümünü başlat"""
        try:
            self.p2p_node = P2PNode(username=self.current_username)
            
            # Mesaj callback'i ayarla
            self.p2p_node.message_callback = self.on_p2p_message_received
            
            self.p2p_node.start()
            self.connection_status["p2p"] = "connected"
            self.network_stats["connection_start_time"] = time.time()
            self.update_p2p_status(True)
            self.add_system_message(f"✅ P2P düğümü başlatıldı - Kullanıcı: {self.current_username}")
            if hasattr(self.p2p_node, 'host') and hasattr(self.p2p_node, 'port'):
                self.add_system_message(f"📍 Adres: {self.p2p_node.host}:{self.p2p_node.port}")
            
            # Kullanıcı listesini düzenli olarak güncelle
            self.schedule_user_list_update()
            
        except Exception as e:
            self.connection_status["p2p"] = "disconnected"
            raise Exception(f"P2P başlatılamadı: {e}")

    def on_p2p_message_received(self, message: str):
        """P2P'den gelen mesajları chat'e ekle"""
        try:
            # Ana thread'de GUI güncelleme yapılmalı
            self.master.after(0, lambda: self.add_chat_message(message))
            # İstatistikleri güncelle
            self.network_stats["messages_received"] += 1
            self.network_stats["bytes_received"] += len(message.encode('utf-8'))
        except Exception as e:
            print(f"[!] Mesaj GUI güncellemesi hatası: {e}")

    def connect_to_server(self):
        """Sunucuya bağlan"""
        host = self.host_entry.get().strip()
        port_str = self.port_entry.get().strip()
        
        if not host or not port_str:
            messagebox.showerror("Hata", "Host ve port bilgilerini girin!")
            return
            
        if not self.current_username:
            messagebox.showerror("Hata", "Önce bir bağlantı türü başlatın!")
            return
            
        try:
            port = int(port_str)
            conn_type = self.connection_type.get()
            
            if conn_type == "p2p":
                if not self.p2p_node:
                    messagebox.showerror("Hata", "Önce P2P düğümünü başlatın!")
                    return
                    
                # Kendine bağlanmayı engelle
                if host in ["localhost", "127.0.0.1"] and port == self.p2p_node.port:
                    messagebox.showwarning("Uyarı", f"Kendi adresinize bağlanamazsınız!\n\nSizin adresiniz: {self.p2p_node.host}:{self.p2p_node.port}\nFarklı bir port kullanın.")
                    return
                
                self.add_system_message(f"🔍 P2P bağlantısı deneniyor: {host}:{port}")
                success = self.p2p_node.connect_to_peer(host, port, "Bilinmiyor")
                
                if success:
                    self.add_system_message(f"✅ P2P bağlantısı başarılı: {host}:{port}")
                    self.update_user_list()
                else:
                    self.add_system_message(f"❌ P2P bağlantısı başarısız: {host}:{port}")
                    messagebox.showerror("Hata", f"P2P bağlantısı kurulamadı!\n\nKontrol edin:\n• Hedef adresteki P2P düğümü çalışıyor mu?\n• Port numarası doğru mu?\n• Ağ bağlantısı var mı?")
            else:
                self.add_system_message(f"🔗 {conn_type.upper()} bağlantısı deneniyor: {host}:{port}")
                messagebox.showinfo("Bilgi", f"{conn_type.upper()} istemci bağlantısı henüz implement edilmedi.")
                
        except ValueError:
            messagebox.showerror("Hata", "Geçersiz port numarası!")
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı hatası: {e}")

    def show_network_map(self):
        """Ağ haritasını göster"""
        if not self.p2p_node:
            messagebox.showwarning("Uyarı", "P2P düğümü çalışmıyor!")
            return
            
        # Ana thread'de güvenli çalışacak şekilde pencere aç
        self.master.after(0, self._open_network_window)

    def _open_network_window(self):
        """Ağ haritası penceresini aç"""
        if self.network_window:
            self.network_window.lift()
            return
            
        self.network_window = tk.Toplevel(self.master)
        self.network_window.title("🗺️ P2P Ağ Haritası")
        self.network_window.geometry("800x600")
        self.network_window.configure(bg=DARK_BG)
        
        # Matplotlib figürü
        fig = plt.Figure(figsize=(10, 6), dpi=100, facecolor=DARK_BG)
        ax = fig.add_subplot(111, facecolor=DARK_BG)
        
        # Canvas
        canvas = FigureCanvasTkAgg(fig, master=self.network_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Grafik çiz
        if self.p2p_node and hasattr(self.p2p_node, 'network_graph'):
            import networkx as nx
            try:
                graph = self.p2p_node.network_graph
                
                if len(graph.nodes()) > 0:
                    # Node'lar varsa çiz
                    pos = nx.spring_layout(graph, k=2, iterations=50)
                    
                    # Node'ları çiz
                    nx.draw_networkx_nodes(graph, pos, ax=ax,
                                         node_color='lightblue', 
                                         node_size=1500,
                                         alpha=0.8)
                    
                    # Bağlantıları çiz
                    if len(graph.edges()) > 0:
                        nx.draw_networkx_edges(graph, pos, ax=ax,
                                             edge_color='gray', 
                                             width=3,
                                             alpha=0.6)
                    
                    # Etiketleri çiz
                    nx.draw_networkx_labels(graph, pos, ax=ax,
                                          font_size=10, 
                                          font_color='black',
                                          font_weight='bold')
                    
                    # Bilgi metni
                    info_text = f"Düğümler: {len(graph.nodes())}\nBağlantılar: {len(graph.edges())}"
                    ax.text(0.02, 0.98, info_text, transform=ax.transAxes, 
                           verticalalignment='top', fontsize=10,
                           bbox=dict(boxstyle='round,pad=0.5', facecolor='yellow', alpha=0.7))
                else:
                    # Hiç node yok
                    ax.text(0.5, 0.5, f"P2P Düğümü: {self.current_username}\nPort: {self.p2p_node.port}\n\nHenüz bağlantı yok", 
                           transform=ax.transAxes, ha='center', va='center',
                           fontsize=12, color='blue',
                           bbox=dict(boxstyle='round,pad=1', facecolor='lightblue', alpha=0.8))
                           
            except Exception as e:
                ax.text(0.5, 0.5, f"Grafik çizilemedi:\n{e}", 
                       transform=ax.transAxes, ha='center', va='center',
                       color='red', fontsize=10)
        else:
            ax.text(0.5, 0.5, "P2P düğümü çalışmıyor", 
                   transform=ax.transAxes, ha='center', va='center',
                   color='red', fontsize=12)
        
        ax.set_title("P2P Ağ Topolojisi", color=TEXT_COLOR, fontsize=14)
        ax.axis('off')
        canvas.draw()
        
        # Pencere kapatıldığında
        def on_closing():
            self.network_window.destroy()
            self.network_window = None
        
        self.network_window.protocol("WM_DELETE_WINDOW", on_closing)

    def show_p2p_help(self):
        """P2P kullanım talimatlarını göster"""
        help_text = """
🌐 P2P (Peer-to-Peer) Nasıl Kullanılır?

📋 ADIM ADIM REHBERİ:

1️⃣ İLK DÜĞÜMÜ BAŞLATIN:
   • Kullanıcı adı: "Ali" 
   • P2P seçin ve "Başlat" a basın
   • Not edin: Port numarası (örn: 54321)

2️⃣ İKİNCİ DÜĞÜMÜ BAŞLATIN:
   • Yeni pencerede uygulamayı açın
   • Kullanıcı adı: "Veli"
   • P2P seçin ve "Başlat" a basın
   • Port numarası farklı olacak (örn: 54322)

3️⃣ BAĞLANTIN:
   • Host: localhost
   • Port: 54321 (Ali'nin portu)
   • "Bağlan" a basın

4️⃣ ÜÇÜNCÜ DÜĞÜM EKLEYİN:
   • Üçüncü pencerede "Ayşe" ile başlayın
   • Ali'ye VEYA Veli'ye bağlanın
   • Her iki yönden de bağlanabilirsiniz

🗺️ AĞ HARİTASINDA GÖRECEK.LERİNİZ:
   • Mavi daireler = Kullanıcılar
   • Gri çizgiler = Bağlantılar
   • İsimler = Kullanıcı adları

💬 MESAJ GÖNDERME:
   • Alt kısımdaki mesaj kutusuna yazın
   • Enter'a basın veya "Gönder" e tıklayın
   • Tüm bağlı düğümlere yayınlanır

⚠️ DİKKAT:
   • Her düğüm farklı portta çalışmalı
   • Sadece bir bağlantı türü aktif olabilir
   • Localhost yerine gerçek IP de kullanabilirsiniz
        """
        
        help_window = tk.Toplevel(self.master)
        help_window.title("P2P Kullanım Kılavuzu")
        help_window.geometry("600x500")
        help_window.configure(bg=DARK_BG)
        
        text_widget = scrolledtext.ScrolledText(
            help_window,
            bg=DARK_BG, fg=TEXT_COLOR,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            padx=10, pady=10
        )
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)

    def update_tcp_status(self, is_active: bool):
        """TCP durum göstergesini güncelle"""
        if is_active:
            color = self.current_theme["success"]
            text = "TCP: 🟢 Bağlı"
            status = "connected"
        else:
            color = self.current_theme["error"]
            text = "TCP: 🔴 Kapalı"
            status = "disconnected"
        
        self.tcp_indicator.delete("all")
        # Animasyonlu gösterge
        self.tcp_indicator.create_oval(2, 2, 13, 13, fill=color, outline=self.current_theme["border"], width=2)
        if is_active:
            self.tcp_indicator.create_oval(5, 5, 10, 10, fill=self.current_theme["bg"], outline="")
        
        self.tcp_status_label.config(text=text, fg=color)
        self.connection_status["tcp"] = status

    def update_udp_status(self, is_active: bool):
        """UDP durum göstergesini güncelle"""
        if is_active:
            color = self.current_theme["success"]
            text = "UDP: 🟢 Bağlı"
            status = "connected"
        else:
            color = self.current_theme["error"]
            text = "UDP: 🔴 Kapalı"
            status = "disconnected"
        
        self.udp_indicator.delete("all")
        self.udp_indicator.create_oval(2, 2, 13, 13, fill=color, outline=self.current_theme["border"], width=2)
        if is_active:
            self.udp_indicator.create_oval(5, 5, 10, 10, fill=self.current_theme["bg"], outline="")
        
        self.udp_status_label.config(text=text, fg=color)
        self.connection_status["udp"] = status

    def update_p2p_status(self, is_active: bool):
        """P2P durum göstergesini güncelle"""
        if is_active:
            color = self.current_theme["success"]
            text = "P2P: 🟢 Bağlı"
            status = "connected"
        else:
            color = self.current_theme["error"]
            text = "P2P: 🔴 Kapalı"
            status = "disconnected"
        
        self.p2p_indicator.delete("all")
        self.p2p_indicator.create_oval(2, 2, 13, 13, fill=color, outline=self.current_theme["border"], width=2)
        if is_active:
            self.p2p_indicator.create_oval(5, 5, 10, 10, fill=self.current_theme["bg"], outline="")
        
        self.p2p_status_label.config(text=text, fg=color)
        self.connection_status["p2p"] = status

    def update_user_list(self):
        """Kullanıcı listesini güncelle"""
        # Mevcut öğeleri temizle
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
            
        user_count = 0
        
        # P2P kullanıcıları ekle
        if self.p2p_node and hasattr(self.p2p_node, 'peers'):
            try:
                # Kendini ekle
                self.user_tree.insert("", "end", values=(
                    f"{self.current_username} (Sen)", 
                    "🟢 Aktif", 
                    f"P2P:{self.p2p_node.port}"
                ))
                user_count += 1
                
                # Diğer peer'ları ekle
                for peer_username, peer_info in self.p2p_node.peers.items():
                    # PeerInfo objesi ise
                    if hasattr(peer_info, 'username'):
                        username = peer_info.username
                        is_active = peer_info.is_active
                        host = peer_info.host
                        port = peer_info.port
                    else:
                        # Dict ise (eski format)
                        username = peer_info.get('username', peer_username)
                        is_active = peer_info.get('is_active', True)
                        host = peer_info.get('host', 'unknown')
                        port = peer_info.get('port', 0)
                    
                    status = "🟢 Aktif" if is_active else "🔴 Pasif"
                    connection = f"P2P:{port}"
                    
                    self.user_tree.insert("", "end", values=(username, status, connection))
                    user_count += 1
                    
            except Exception as e:
                self.add_system_message(f"❌ Kullanıcı listesi güncelleme hatası: {e}")
        
        # Kullanıcı sayısını güncelle
        self.user_count_label.config(text=f"Toplam: {user_count} kullanıcı")

    def schedule_user_list_update(self):
        """Kullanıcı listesi güncellemesini zamanla"""
        if self.p2p_node:
            self.update_user_list()
            self.check_p2p_connection_health()
            self.master.after(5000, self.schedule_user_list_update)  # 5 saniyede bir güncelle
            
    def check_p2p_connection_health(self):
        """P2P bağlantısının sağlığını kontrol et"""
        if not self.p2p_node:
            self.update_p2p_status(False)
            return
            
        try:
            # P2P node'un çalışıp çalışmadığını kontrol et
            if not self.p2p_node.is_running:
                self.update_p2p_status(False)
                self.add_system_message("⚠️ P2P düğümü çalışmıyor - bağlantı durduruluyor")
                return
                
            # Aktif peer sayısını kontrol et
            status = self.p2p_node.get_network_status()
            active_peers = status.get("active_peers", 0)
            
            # Hiç aktif peer yoksa uyarı ver ama yeşil kal (çünkü node çalışıyor)
            if active_peers == 0:
                self.update_p2p_status(True)  # Node çalışıyor ama peer yok
            else:
                self.update_p2p_status(True)
                
            # Durum mesajları
            if active_peers == 0:
                self.add_system_message(f"🔍 P2P aktif ama bağlı peer yok (Port: {self.p2p_node.port})")
            else:
                self.add_system_message(f"📡 P2P bağlantısı sağlıklı - {active_peers} aktif peer")
                
        except Exception as e:
            self.update_p2p_status(False)
            self.add_system_message(f"❌ P2P sağlık kontrolü başarısız: {e}")

    def on_user_select(self, event):
        """Kullanıcı seçildiğinde detayları göster"""
        selection = self.user_tree.selection()
        if not selection:
            return
            
        item = self.user_tree.item(selection[0])
        values = item['values']
        
        if values:
            username, status, connection = values
            
            detail_text = f"👤 Kullanıcı: {username}\n"
            detail_text += f"🔗 Bağlantı: {connection}\n"
            detail_text += f"📊 Durum: {status}\n"
            detail_text += f"⏰ Son görülme: Az önce\n"
            
            if self.p2p_node:
                detail_text += f"📡 RTT: -- ms\n"
                detail_text += f"📤 Gönderilen: -- paket\n"
                detail_text += f"📥 Alınan: -- paket"
            
            self.user_detail_text.config(state=tk.NORMAL)
            self.user_detail_text.delete(1.0, tk.END)
            self.user_detail_text.insert(1.0, detail_text)
            self.user_detail_text.config(state=tk.DISABLED)

    def send_message(self, event=None):
        """Mesaj gönder"""
        message = self.message_entry.get().strip()
        if not message:
            return
            
        if not self.current_username:
            messagebox.showerror("Hata", "Önce bağlantı kurun!")
            return
            
        # Mesajı chat'e ekle
        self.add_chat_message(f"{self.current_username}: {message}")
        
        # Mesajı gönder (bağlantı türüne göre)
        try:
            if self.p2p_node:
                sent_count = self.p2p_node.broadcast_message(message)
                if sent_count == 0:
                    self.add_system_message("⚠️ Henüz bağlı peer yok")
                else:
                    self.add_system_message(f"📤 Mesaj {sent_count} peer'a gönderildi")
                    # İstatistikleri güncelle
                    self.network_stats["messages_sent"] += 1
                    self.network_stats["bytes_sent"] += len(message.encode('utf-8'))
        except Exception as e:
            self.add_system_message(f"❌ Mesaj gönderilemedi: {e}")
        
        self.message_entry.delete(0, tk.END)

    def add_chat_message(self, message: str):
        """Chat mesajı ekle"""
        self.chat_display.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
        # Mesajı geçmişe ekle
        self.save_message_to_history(message, "chat")

    def add_system_message(self, message: str):
        """Sistem mesajı ekle"""
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        
        self.system_display.config(state=tk.NORMAL)
        self.system_display.insert(tk.END, f"{full_message}\n")
        self.system_display.see(tk.END)
        self.system_display.config(state=tk.DISABLED)
        
        # Sistem mesajını geçmişe ekle
        self.save_message_to_history(full_message, "system")

    # ========================= YENİ ÖZELLİKLER =========================
    
    def setup_menu_bar(self):
        """Menü çubuğunu kur"""
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        
        # Görünüm menüsü
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Görünüm", menu=view_menu)
        view_menu.add_command(label="🌙 Koyu Mod", command=lambda: self.switch_theme(True))
        view_menu.add_command(label="☀️ Açık Mod", command=lambda: self.switch_theme(False))
        view_menu.add_separator()
        view_menu.add_command(label="📊 Ağ İstatistikleri", command=self.show_network_stats)
        view_menu.add_command(label="📜 Mesaj Geçmişi", command=self.show_message_history)
        
        # Araçlar menüsü
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Araçlar", menu=tools_menu)
        tools_menu.add_command(label="🗺️ Ağ Haritası", command=self.show_network_map)
        tools_menu.add_command(label="🧹 Geçmişi Temizle", command=self.clear_message_history)
        tools_menu.add_separator()
        tools_menu.add_command(label="🔧 Ayarlar", command=self.show_settings)
        
        # Yardım menüsü
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Yardım", menu=help_menu)
        help_menu.add_command(label="❓ P2P Kullanımı", command=self.show_p2p_help)
        help_menu.add_command(label="ℹ️ Hakkında", command=self.show_about)

    def setup_status_bar(self):
        """Alt durum çubuğunu kur"""
        self.status_frame = tk.Frame(self.master, bg=self.current_theme["panel_bg"], height=30)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_frame.pack_propagate(False)
        
        # Sol taraf - Bağlantı durumu
        left_status = tk.Frame(self.status_frame, bg=self.current_theme["panel_bg"])
        left_status.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.connection_status_label = tk.Label(left_status, 
                                              text="🔴 Bağlantı Yok",
                                              bg=self.current_theme["panel_bg"], 
                                              fg=self.current_theme["error"],
                                              font=("Segoe UI", 9))
        self.connection_status_label.pack(side=tk.LEFT)
        
        # Orta - İstatistikler
        middle_status = tk.Frame(self.status_frame, bg=self.current_theme["panel_bg"])
        middle_status.pack(side=tk.LEFT, expand=True, padx=20)
        
        self.stats_label = tk.Label(middle_status,
                                   text="📤 0 | 📥 0 | ⏱️ 0ms",
                                   bg=self.current_theme["panel_bg"],
                                   fg=self.current_theme["text_color"],
                                   font=("Segoe UI", 9))
        self.stats_label.pack()
        
        # Sağ taraf - Tema değiştirici
        right_status = tk.Frame(self.status_frame, bg=self.current_theme["panel_bg"])
        right_status.pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.theme_btn = tk.Button(right_status,
                                  text="🌙" if self.is_dark_mode else "☀️",
                                  command=self.toggle_theme,
                                  bg=self.current_theme["button_bg"],
                                  fg=self.current_theme["button_fg"],
                                  font=("Segoe UI", 8),
                                  width=3, height=1,
                                  relief="flat")
        self.theme_btn.pack(side=tk.RIGHT)

    def toggle_theme(self):
        """Tema değiştir"""
        self.switch_theme(not self.is_dark_mode)

    def switch_theme(self, is_dark: bool):
        """Tema değiştir"""
        self.is_dark_mode = is_dark
        self.current_theme = DARK_THEME if is_dark else LIGHT_THEME
        
        # Global değişkenleri güncelle
        global DARK_BG, PANEL_BG, BUTTON_BG, BUTTON_FG, ENTRY_BG, TEXT_COLOR
        global SECONDARY, PRIMARY, SUCCESS_COLOR, ERROR_COLOR, WARNING_COLOR
        
        DARK_BG = self.current_theme["bg"]
        PANEL_BG = self.current_theme["panel_bg"]
        BUTTON_BG = self.current_theme["button_bg"]
        BUTTON_FG = self.current_theme["button_fg"]
        ENTRY_BG = self.current_theme["entry_bg"]
        TEXT_COLOR = self.current_theme["text_color"]
        SECONDARY = self.current_theme["secondary"]
        PRIMARY = self.current_theme["primary"]
        SUCCESS_COLOR = self.current_theme["success"]
        ERROR_COLOR = self.current_theme["error"]
        WARNING_COLOR = self.current_theme["warning"]
        
        # UI'yi yeniden oluştur
        self.refresh_ui()
        
    def refresh_ui(self):
        """UI'yi yeni tema ile yenile"""
        # Ana pencereyi güncelle
        self.master.configure(bg=self.current_theme["bg"])
        
        # Tema butonunu güncelle
        if hasattr(self, 'theme_btn'):
            self.theme_btn.config(
                text="🌙" if self.is_dark_mode else "☀️",
                bg=self.current_theme["button_bg"],
                fg=self.current_theme["button_fg"]
            )
        
        # Status bar'ı güncelle
        if hasattr(self, 'status_frame'):
            self.status_frame.config(bg=self.current_theme["panel_bg"])
            
        if hasattr(self, 'connection_status_label'):
            self.connection_status_label.config(bg=self.current_theme["panel_bg"])
            
        if hasattr(self, 'stats_label'):
            self.stats_label.config(
                bg=self.current_theme["panel_bg"],
                fg=self.current_theme["text_color"]
            )
        
        # Chat alanını güncelle
        if hasattr(self, 'chat_display'):
            self.chat_display.config(
                bg=self.current_theme["bg"],
                fg=self.current_theme["text_color"]
            )
            
        if hasattr(self, 'system_display'):
            self.system_display.config(
                bg=self.current_theme["bg"],
                fg=self.current_theme["warning"]
            )
            
        if hasattr(self, 'message_entry'):
            self.message_entry.config(
                bg=self.current_theme["entry_bg"],
                fg=self.current_theme["text_color"],
                insertbackground=self.current_theme["text_color"]
            )
            
        if hasattr(self, 'send_btn'):
            self.send_btn.config(
                bg=self.current_theme["button_bg"],
                fg=self.current_theme["button_fg"]
            )
        
        # Kullanıcı girişi alanını güncelle
        if hasattr(self, 'username_entry'):
            self.username_entry.config(
                bg=self.current_theme["entry_bg"],
                fg=self.current_theme["text_color"],
                insertbackground=self.current_theme["text_color"]
            )
            
        if hasattr(self, 'host_entry'):
            self.host_entry.config(
                bg=self.current_theme["entry_bg"],
                fg=self.current_theme["text_color"]
            )
            
        if hasattr(self, 'port_entry'):
            self.port_entry.config(
                bg=self.current_theme["entry_bg"],
                fg=self.current_theme["text_color"]
            )
        
        # Butonları güncelle
        if hasattr(self, 'start_btn'):
            self.start_btn.config(
                bg=self.current_theme["success"],
                fg=self.current_theme["button_fg"]
            )
            
        if hasattr(self, 'stop_btn'):
            self.stop_btn.config(
                bg=self.current_theme["error"],
                fg=self.current_theme["button_fg"]
            )
            
        if hasattr(self, 'connect_btn'):
            self.connect_btn.config(
                bg=self.current_theme["button_bg"],
                fg=self.current_theme["button_fg"]
            )
            
        if hasattr(self, 'network_map_btn'):
            self.network_map_btn.config(
                bg=self.current_theme["secondary"],
                fg=self.current_theme["button_fg"]
            )
        
        # Kullanıcı sayısı etiketini güncelle
        if hasattr(self, 'user_count_label'):
            self.user_count_label.config(
                bg=self.current_theme["panel_bg"],
                fg=self.current_theme["muted"]
            )
            
        if hasattr(self, 'user_detail_text'):
            self.user_detail_text.config(
                bg=self.current_theme["bg"],
                fg=self.current_theme["text_color"]
            )
        
        # Durum göstergelerini güncelle
        self.update_tcp_status(self.connection_status.get("tcp") == "connected")
        self.update_udp_status(self.connection_status.get("udp") == "connected")
        self.update_p2p_status(self.connection_status.get("p2p") == "connected")
            
        self.add_system_message(f"🎨 Tema değiştirildi: {'Koyu' if self.is_dark_mode else 'Açık'} mod")

    def save_message_to_history(self, message: str, msg_type: str):
        """Mesajı geçmişe kaydet"""
        msg_entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "type": msg_type,
            "username": self.current_username
        }
        self.message_history.append(msg_entry)
        
        # Geçmişi dosyaya kaydet (en son 1000 mesaj)
        if len(self.message_history) > 1000:
            self.message_history = self.message_history[-1000:]
        
        self.save_message_history()

    def load_message_history(self):
        """Mesaj geçmişini yükle"""
        try:
            if os.path.exists("message_history.json"):
                with open("message_history.json", "r", encoding="utf-8") as f:
                    self.message_history = json.load(f)
        except Exception as e:
            self.message_history = []

    def save_message_history(self):
        """Mesaj geçmişini kaydet"""
        try:
            with open("message_history.json", "w", encoding="utf-8") as f:
                json.dump(self.message_history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            pass

    def show_message_history(self):
        """Mesaj geçmişi penceresini göster"""
        history_window = tk.Toplevel(self.master)
        history_window.title("📜 Mesaj Geçmişi")
        history_window.geometry("800x600")
        history_window.configure(bg=self.current_theme["bg"])
        
        # Üst panel - Arama ve filtreler
        search_frame = tk.Frame(history_window, bg=self.current_theme["panel_bg"])
        search_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        tk.Label(search_frame, text="🔍 Ara:", 
                bg=self.current_theme["panel_bg"], 
                fg=self.current_theme["text_color"],
                font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 5))
        
        search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=search_var,
                               bg=self.current_theme["entry_bg"],
                               fg=self.current_theme["text_color"],
                               font=("Segoe UI", 10))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        # Filtre seçenekleri
        filter_frame = tk.Frame(search_frame, bg=self.current_theme["panel_bg"])
        filter_frame.pack(side=tk.RIGHT)
        
        show_all = tk.BooleanVar(value=True)
        show_chat = tk.BooleanVar(value=True)
        show_system = tk.BooleanVar(value=True)
        
        tk.Checkbutton(filter_frame, text="Tümü", variable=show_all,
                      bg=self.current_theme["panel_bg"],
                      fg=self.current_theme["text_color"]).pack(side=tk.LEFT)
        tk.Checkbutton(filter_frame, text="Chat", variable=show_chat,
                      bg=self.current_theme["panel_bg"],
                      fg=self.current_theme["text_color"]).pack(side=tk.LEFT)
        tk.Checkbutton(filter_frame, text="Sistem", variable=show_system,
                      bg=self.current_theme["panel_bg"],
                      fg=self.current_theme["text_color"]).pack(side=tk.LEFT)
        
        # Mesaj listesi
        history_text = scrolledtext.ScrolledText(history_window,
                                                bg=self.current_theme["bg"],
                                                fg=self.current_theme["text_color"],
                                                font=("Segoe UI", 10),
                                                wrap=tk.WORD)
        history_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Alt panel - Butonlar
        button_frame = tk.Frame(history_window, bg=self.current_theme["bg"])
        button_frame.pack(fill=tk.X, padx=10, pady=(5, 10))
        
        tk.Button(button_frame, text="🔄 Yenile",
                 command=lambda: self.refresh_history_display(history_text, search_var.get()),
                 bg=self.current_theme["button_bg"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(button_frame, text="📋 Kopyala",
                 command=lambda: self.copy_history_to_clipboard(history_text),
                 bg=self.current_theme["secondary"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(button_frame, text="🧹 Temizle",
                 command=lambda: self.clear_message_history(),
                 bg=self.current_theme["error"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.RIGHT)
        
        # İlk yükleme
        self.refresh_history_display(history_text, "")
        
        # Arama fonksiyonu
        def on_search(*args):
            self.refresh_history_display(history_text, search_var.get())
        
        search_var.trace('w', on_search)

    def refresh_history_display(self, text_widget, search_term=""):
        """Geçmiş görüntüsünü yenile"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)
        
        displayed_count = 0
        for entry in reversed(self.message_history[-200:]):  # Son 200 mesaj
            message = entry.get("message", "")
            msg_type = entry.get("type", "chat")
            timestamp = entry.get("timestamp", "")
            
            if search_term and search_term.lower() not in message.lower():
                continue
                
            # Timestamp'i formatla
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_time = timestamp
            
            type_icon = "💬" if msg_type == "chat" else "🔧"
            text_widget.insert(tk.END, f"{type_icon} [{formatted_time}] {message}\n")
            displayed_count += 1
        
        if displayed_count == 0:
            text_widget.insert(tk.END, "📝 Görüntülenecek mesaj bulunamadı.\n")
        
        text_widget.config(state=tk.DISABLED)

    def copy_history_to_clipboard(self, text_widget):
        """Geçmişi panoya kopyala"""
        content = text_widget.get(1.0, tk.END)
        self.master.clipboard_clear()
        self.master.clipboard_append(content)
        self.add_system_message("📋 Mesaj geçmişi panoya kopyalandı")

    def clear_message_history(self):
        """Mesaj geçmişini temizle"""
        if messagebox.askyesno("Onay", "Tüm mesaj geçmişi silinecek. Emin misiniz?"):
            self.message_history.clear()
            self.save_message_history()
            self.add_system_message("🧹 Mesaj geçmişi temizlendi")

    def show_network_stats(self):
        """Ağ istatistikleri penceresini göster"""
        if self.stats_window and self.stats_window.winfo_exists():
            self.stats_window.lift()
            return
            
        self.stats_window = tk.Toplevel(self.master)
        self.stats_window.title("📊 Ağ İstatistikleri")
        self.stats_window.geometry("600x500")
        self.stats_window.configure(bg=self.current_theme["bg"])
        
        # Ana frame
        main_frame = tk.Frame(self.stats_window, bg=self.current_theme["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Genel istatistikler
        general_frame = tk.LabelFrame(main_frame, text="📈 Genel İstatistikler",
                                     bg=self.current_theme["panel_bg"],
                                     fg=self.current_theme["text_color"],
                                     font=("Segoe UI", 12, "bold"))
        general_frame.pack(fill=tk.X, pady=(0, 10))
        
        # İstatistik etiketleri
        self.stats_labels = {}
        stats_info = [
            ("messages_sent", "📤 Gönderilen Mesajlar"),
            ("messages_received", "📥 Alınan Mesajlar"),
            ("bytes_sent", "📊 Gönderilen Veri"),
            ("bytes_received", "📊 Alınan Veri"),
            ("connection_uptime", "⏱️ Bağlantı Süresi"),
            ("last_ping", "📡 Son Ping"),
            ("packet_loss", "📉 Paket Kaybı")
        ]
        
        for key, label in stats_info:
            frame = tk.Frame(general_frame, bg=self.current_theme["panel_bg"])
            frame.pack(fill=tk.X, padx=10, pady=2)
            
            tk.Label(frame, text=label,
                    bg=self.current_theme["panel_bg"],
                    fg=self.current_theme["text_color"],
                    font=("Segoe UI", 10)).pack(side=tk.LEFT)
            
            value_label = tk.Label(frame, text="0",
                                  bg=self.current_theme["panel_bg"],
                                  fg=self.current_theme["primary"],
                                  font=("Segoe UI", 10, "bold"))
            value_label.pack(side=tk.RIGHT)
            self.stats_labels[key] = value_label
        
        # Bağlantı durumu
        connection_frame = tk.LabelFrame(main_frame, text="🌐 Bağlantı Durumu",
                                        bg=self.current_theme["panel_bg"],
                                        fg=self.current_theme["text_color"],
                                        font=("Segoe UI", 12, "bold"))
        connection_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.connection_status_text = tk.Text(connection_frame,
                                             bg=self.current_theme["bg"],
                                             fg=self.current_theme["text_color"],
                                             font=("Segoe UI", 10),
                                             height=8,
                                             state=tk.DISABLED)
        self.connection_status_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Alt butonlar
        button_frame = tk.Frame(main_frame, bg=self.current_theme["bg"])
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        tk.Button(button_frame, text="🔄 Yenile",
                 command=self.update_network_stats_display,
                 bg=self.current_theme["button_bg"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.LEFT)
        
        tk.Button(button_frame, text="📊 Sıfırla",
                 command=self.reset_network_stats,
                 bg=self.current_theme["warning"],
                 fg="black").pack(side=tk.LEFT, padx=(5, 0))
        
        tk.Button(button_frame, text="❌ Kapat",
                 command=self.stats_window.destroy,
                 bg=self.current_theme["error"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.RIGHT)
        
        # İlk güncelleme
        self.update_network_stats_display()
        
        # Otomatik güncelleme
        self.schedule_stats_update()

    def update_network_stats_display(self):
        """İstatistik görüntüsünü güncelle"""
        if not hasattr(self, 'stats_labels'):
            return
            
        # Bağlantı süresini hesapla
        if self.network_stats["connection_start_time"]:
            uptime = time.time() - self.network_stats["connection_start_time"]
            uptime_str = f"{int(uptime//3600):02d}:{int((uptime%3600)//60):02d}:{int(uptime%60):02d}"
        else:
            uptime_str = "00:00:00"
        
        # İstatistikleri güncelle
        stats_display = {
            "messages_sent": str(self.network_stats["messages_sent"]),
            "messages_received": str(self.network_stats["messages_received"]),
            "bytes_sent": f"{self.network_stats['bytes_sent']} bytes",
            "bytes_received": f"{self.network_stats['bytes_received']} bytes",
            "connection_uptime": uptime_str,
            "last_ping": f"{self.network_stats['last_ping']} ms",
            "packet_loss": f"{self.network_stats['packet_loss']:.1f}%"
        }
        
        for key, value in stats_display.items():
            if key in self.stats_labels:
                self.stats_labels[key].config(text=value)
        
        # Bağlantı durumu metnini güncelle
        if hasattr(self, 'connection_status_text'):
            self.connection_status_text.config(state=tk.NORMAL)
            self.connection_status_text.delete(1.0, tk.END)
            
            status_text = "=== BAĞLANTI DURUMU ===\n\n"
            for conn_type, status in self.connection_status.items():
                icon = "🟢" if status == "connected" else "🟡" if status == "connecting" else "🔴"
                status_text += f"{icon} {conn_type.upper()}: {status}\n"
            
            status_text += f"\n=== AĞ BİLGİLERİ ===\n"
            status_text += f"Aktif Kullanıcı: {self.current_username}\n"
            
            if self.p2p_node:
                status_text += f"P2P Port: {self.p2p_node.port}\n"
                status_text += f"Peer Sayısı: {len(self.p2p_node.peers) if hasattr(self.p2p_node, 'peers') else 0}\n"
            
            self.connection_status_text.insert(tk.END, status_text)
            self.connection_status_text.config(state=tk.DISABLED)

    def schedule_stats_update(self):
        """İstatistik güncellemesini zamanla"""
        if self.stats_window and self.stats_window.winfo_exists():
            self.update_network_stats_display()
            self.master.after(2000, self.schedule_stats_update)

    def reset_network_stats(self):
        """Ağ istatistiklerini sıfırla"""
        if messagebox.askyesno("Onay", "Tüm ağ istatistikleri sıfırlanacak. Emin misiniz?"):
            self.network_stats = {
                "messages_sent": 0,
                "messages_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "connection_uptime": 0,
                "last_ping": 0,
                "packet_loss": 0,
                "connection_start_time": time.time() if any(s == "connected" for s in self.connection_status.values()) else None
            }
            self.update_network_stats_display()
            self.add_system_message("📊 Ağ istatistikleri sıfırlandı")

    def start_stats_updater(self):
        """İstatistik güncelleyiciyi başlat"""
        def update_stats():
            # Durum çubuğu istatistiklerini güncelle
            if hasattr(self, 'stats_label'):
                sent = self.network_stats["messages_sent"]
                received = self.network_stats["messages_received"]
                ping = self.network_stats["last_ping"]
                self.stats_label.config(text=f"📤 {sent} | 📥 {received} | ⏱️ {ping}ms")
            
            # Bağlantı durumu güncelle
            if hasattr(self, 'connection_status_label'):
                active_connections = [k for k, v in self.connection_status.items() if v == "connected"]
                if active_connections:
                    conn_text = ", ".join(conn.upper() for conn in active_connections)
                    self.connection_status_label.config(
                        text=f"🟢 Bağlı: {conn_text}",
                        fg=self.current_theme["success"]
                    )
                else:
                    self.connection_status_label.config(
                        text="🔴 Bağlantı Yok",
                        fg=self.current_theme["error"]
                    )
            
            self.master.after(1000, update_stats)
        
        update_stats()

    def show_settings(self):
        """Ayarlar penceresini göster"""
        settings_window = tk.Toplevel(self.master)
        settings_window.title("🔧 Ayarlar")
        settings_window.geometry("500x400")
        settings_window.configure(bg=self.current_theme["bg"])
        
        # Tema ayarları
        theme_frame = tk.LabelFrame(settings_window, text="🎨 Tema Ayarları",
                                   bg=self.current_theme["panel_bg"],
                                   fg=self.current_theme["text_color"],
                                   font=("Segoe UI", 12, "bold"))
        theme_frame.pack(fill=tk.X, padx=10, pady=10)
        
        theme_var = tk.BooleanVar(value=self.is_dark_mode)
        tk.Radiobutton(theme_frame, text="🌙 Koyu Mod", variable=theme_var, value=True,
                      bg=self.current_theme["panel_bg"],
                      fg=self.current_theme["text_color"]).pack(anchor="w", padx=10, pady=5)
        tk.Radiobutton(theme_frame, text="☀️ Açık Mod", variable=theme_var, value=False,
                      bg=self.current_theme["panel_bg"],
                      fg=self.current_theme["text_color"]).pack(anchor="w", padx=10, pady=5)
        
        # Uygulama ayarları
        app_frame = tk.LabelFrame(settings_window, text="⚙️ Uygulama Ayarları",
                                 bg=self.current_theme["panel_bg"],
                                 fg=self.current_theme["text_color"],
                                 font=("Segoe UI", 12, "bold"))
        app_frame.pack(fill=tk.X, padx=10, pady=10)
        
        auto_save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(app_frame, text="💾 Mesajları otomatik kaydet",
                      variable=auto_save_var,
                      bg=self.current_theme["panel_bg"],
                      fg=self.current_theme["text_color"]).pack(anchor="w", padx=10, pady=5)
        
        # Butonlar
        button_frame = tk.Frame(settings_window, bg=self.current_theme["bg"])
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def apply_settings():
            self.switch_theme(theme_var.get())
            settings_window.destroy()
            self.add_system_message("✅ Ayarlar uygulandı")
        
        tk.Button(button_frame, text="✅ Uygula",
                 command=apply_settings,
                 bg=self.current_theme["success"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.LEFT)
        
        tk.Button(button_frame, text="❌ İptal",
                 command=settings_window.destroy,
                 bg=self.current_theme["error"],
                 fg=self.current_theme["button_fg"]).pack(side=tk.RIGHT)

    def show_about(self):
        """Hakkında penceresini göster"""
        about_text = """
🚀 Modern Chat Uygulaması v3.0

✨ ÖZELLİKLER:
• P2P, TCP, UDP bağlantı desteği
• Gelişmiş durum göstergeleri
• Ağ istatistikleri takibi
• Mesaj geçmişi yönetimi
• Açık/Koyu tema desteği
• Gerçek zamanlı ağ görselleştirme

👨‍💻 Geliştirici: Modern Chat Team
📅 Sürüm: 3.0 (2024)
🛠️ Teknoloji: Python, Tkinter
"""
        messagebox.showinfo("Hakkında", about_text)

    def clear_current_chat(self):
        """Mevcut chat ekranını temizle"""
        if messagebox.askyesno("Onay", "Chat ekranı temizlenecek. Emin misiniz?"):
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state=tk.DISABLED)
            self.add_system_message("🧹 Chat ekranı temizlendi")

    def clear_system_messages(self):
        """Sistem mesajlarını temizle"""
        self.system_display.config(state=tk.NORMAL)
        self.system_display.delete(1.0, tk.END)
        self.system_display.config(state=tk.DISABLED)

# Ana uygulama
if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ModernChatApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Uygulama başlatma hatası: {e}")
        input("Çıkmak için Enter'a basın...") 