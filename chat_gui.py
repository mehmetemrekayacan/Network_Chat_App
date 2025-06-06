"""
Modern arayüzlü chat uygulaması (Tkinter GUI).
- Merkezi bağlantı kontrolü (TCP, UDP ve P2P)
- Ağ topolojisi görselleştirme
- Gerçek zamanlı ağ durumu izleme
- Gelişmiş RTT ölçümü
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from typing import Optional, Dict, Any
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
matplotlib.use('TkAgg')  # Tkinter backend kullan

# Sunucu modüllerini import et
import server
import udp_server
from p2p_node import P2PNode

# Modern tema renkleri
DARK_BG = "#2B2B2B"
PANEL_BG = "#3C3C3C"
BUTTON_BG = "#007ACC"
BUTTON_FG = "#FFFFFF"
ENTRY_BG = "#4D4D4D"
TEXT_COLOR = "#FFFFFF"
SECONDARY = "#005A9E"
PRIMARY = "#007ACC"
SUCCESS_COLOR = "#28A745"
ERROR_COLOR = "#DC3545"
WARNING_COLOR = "#FFC107"

class ModernChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Modern Chat Uygulaması v2.0")
        self.master.geometry("1200x800")
        self.master.configure(bg=DARK_BG)
        
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
        
        # UI bileşenleri
        self.connection_type = tk.StringVar(value="p2p")
        
        self.setup_ui()

    def setup_ui(self):
        """Ana arayüzü kur"""
        # Ana çerçeve
        main_frame = tk.Frame(self.master, bg=DARK_BG)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Sol panel - Chat alanı
        self.setup_chat_area(main_frame)
        
        # Orta panel - Kontrol paneli
        self.setup_control_panel(main_frame)
        
        # Sağ panel - Kullanıcılar
        self.setup_users_panel(main_frame)

    def setup_chat_area(self, parent):
        """Chat alanını kur"""
        chat_frame = tk.Frame(parent, bg=PANEL_BG, relief="raised", bd=1)
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Başlık
        tk.Label(chat_frame, text="💬 Sohbet Alanı", 
                bg=PANEL_BG, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Chat mesajları
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            bg=DARK_BG, fg=TEXT_COLOR,
            font=("Segoe UI", 11),
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=15
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Mesaj giriş alanı
        msg_frame = tk.Frame(chat_frame, bg=PANEL_BG)
        msg_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.message_entry = tk.Entry(
            msg_frame,
            bg=ENTRY_BG, fg=TEXT_COLOR,
            font=("Segoe UI", 11),
            relief="flat",
            insertbackground=TEXT_COLOR
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        self.send_btn = tk.Button(
            msg_frame, text="Gönder",
            command=self.send_message,
            bg=BUTTON_BG, fg=BUTTON_FG,
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        )
        self.send_btn.pack(side=tk.RIGHT)
        
        # Sistem mesajları
        tk.Label(chat_frame, text="🔧 Sistem Mesajları", 
                bg=PANEL_BG, fg=TEXT_COLOR,
                font=("Segoe UI", 12, "bold")).pack(pady=(10, 5))
        
        self.system_display = scrolledtext.ScrolledText(
            chat_frame,
            bg=DARK_BG, fg=WARNING_COLOR,
            font=("Segoe UI", 10),
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=8
        )
        self.system_display.pack(fill=tk.X, padx=10, pady=(0, 10))

    def setup_control_panel(self, parent):
        """Merkezi kontrol panelini kur"""
        control_frame = tk.Frame(parent, bg=PANEL_BG, relief="raised", bd=1)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Başlık
        tk.Label(control_frame, text="⚙️ Bağlantı Kontrolü", 
                bg=PANEL_BG, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Kullanıcı adı girişi
        user_frame = tk.LabelFrame(control_frame, text="👤 Kullanıcı Bilgileri",
                                  bg=PANEL_BG, fg=TEXT_COLOR,
                                  font=("Segoe UI", 11, "bold"))
        user_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Label(user_frame, text="Kullanıcı Adı:",
                bg=PANEL_BG, fg=TEXT_COLOR,
                font=("Segoe UI", 10)).pack(anchor="w", padx=5, pady=(5, 0))
        
        self.username_entry = tk.Entry(user_frame, width=25,
                                     font=("Segoe UI", 11),
                                     bg=ENTRY_BG, fg=TEXT_COLOR,
                                     relief="flat",
                                     insertbackground=TEXT_COLOR)
        self.username_entry.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        # Bağlantı türü seçimi
        conn_frame = tk.LabelFrame(control_frame, text="🌐 Bağlantı Türü",
                                  bg=PANEL_BG, fg=TEXT_COLOR,
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
                          bg=PANEL_BG, fg=TEXT_COLOR,
                          selectcolor=PANEL_BG,
                          activebackground=PANEL_BG,
                          activeforeground=TEXT_COLOR,
                          font=("Segoe UI", 10)).pack(anchor="w", padx=5, pady=2)
        
        # Sunucu kontrolleri
        server_frame = tk.LabelFrame(control_frame, text="🖥️ Sunucu Kontrolü",
                                    bg=PANEL_BG, fg=TEXT_COLOR,
                                    font=("Segoe UI", 11, "bold"))
        server_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Durum göstergeleri
        status_frame = tk.Frame(server_frame, bg=PANEL_BG)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Durum göstergesi fonksiyonu
        def create_status_indicator(parent, text):
            frame = tk.Frame(parent, bg=PANEL_BG)
            frame.pack(fill=tk.X, pady=2)
            
            indicator = tk.Canvas(frame, width=15, height=15, bg=PANEL_BG, highlightthickness=0)
            indicator.pack(side=tk.LEFT, padx=(0, 5))
            indicator.create_oval(3, 3, 12, 12, fill=ERROR_COLOR, outline="#CC5555")
            
            label = tk.Label(frame, text=text,
                           bg=PANEL_BG, fg=ERROR_COLOR,
                           font=("Segoe UI", 10))
            label.pack(side=tk.LEFT)
            
            return indicator, label
        
        self.tcp_indicator, self.tcp_status_label = create_status_indicator(status_frame, "TCP: Kapalı")
        self.udp_indicator, self.udp_status_label = create_status_indicator(status_frame, "UDP: Kapalı")
        self.p2p_indicator, self.p2p_status_label = create_status_indicator(status_frame, "P2P: Kapalı")
        
        # Kontrol butonları
        button_frame = tk.Frame(server_frame, bg=PANEL_BG)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_btn = tk.Button(button_frame, text="🚀 Başlat",
                                  command=self.start_connection,
                                  bg=SUCCESS_COLOR, fg=BUTTON_FG,
                                  font=("Segoe UI", 11, "bold"),
                                  relief="flat", width=12)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = tk.Button(button_frame, text="⏹️ Durdur",
                                 command=self.stop_connection,
                                 bg=ERROR_COLOR, fg=BUTTON_FG,
                                 font=("Segoe UI", 11, "bold"),
                                 relief="flat", width=12)
        self.stop_btn.pack(side=tk.LEFT)
        
        # İstemci bağlantısı
        client_frame = tk.LabelFrame(control_frame, text="🔗 Bağlantı Kur",
                                    bg=PANEL_BG, fg=TEXT_COLOR,
                                    font=("Segoe UI", 11, "bold"))
        client_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Host ve Port
        addr_frame = tk.Frame(client_frame, bg=PANEL_BG)
        addr_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(addr_frame, text="Host:", bg=PANEL_BG, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(side=tk.LEFT)
        self.host_entry = tk.Entry(addr_frame, width=12, bg=ENTRY_BG, fg=TEXT_COLOR, font=("Segoe UI", 10), relief="flat")
        self.host_entry.pack(side=tk.LEFT, padx=5)
        self.host_entry.insert(0, "localhost")
        
        tk.Label(addr_frame, text="Port:", bg=PANEL_BG, fg=TEXT_COLOR, font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(10, 0))
        self.port_entry = tk.Entry(addr_frame, width=8, bg=ENTRY_BG, fg=TEXT_COLOR, font=("Segoe UI", 10), relief="flat")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "12345")
        
        # Bağlan butonu
        self.connect_btn = tk.Button(client_frame, text="🔗 Bağlan",
                                    command=self.connect_to_server,
                                    bg=BUTTON_BG, fg=BUTTON_FG,
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat")
        self.connect_btn.pack(pady=(5, 2))
        
        # P2P için ek bilgi
        p2p_info = tk.Label(client_frame, 
                           text="💡 P2P için birden fazla farklı porta bağlanabilirsiniz",
                           bg=PANEL_BG, fg="#CCCCCC",
                           font=("Segoe UI", 8),
                           wraplength=200)
        p2p_info.pack(pady=(0, 5))
        
        # Ağ araçları
        tools_frame = tk.LabelFrame(control_frame, text="🛠️ Ağ Araçları",
                                   bg=PANEL_BG, fg=TEXT_COLOR,
                                   font=("Segoe UI", 11, "bold"))
        tools_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.network_map_btn = tk.Button(tools_frame, text="🗺️ Ağ Haritası",
                                        command=self.show_network_map,
                                        bg=SECONDARY, fg=BUTTON_FG,
                                        font=("Segoe UI", 10, "bold"),
                                        relief="flat")
        self.network_map_btn.pack(fill=tk.X, padx=5, pady=(5, 2))
        
        # Yardım butonu
        help_btn = tk.Button(tools_frame, text="❓ P2P Nasıl Kullanılır?",
                            command=self.show_p2p_help,
                            bg=WARNING_COLOR, fg="black",
                            font=("Segoe UI", 9, "bold"),
                            relief="flat")
        help_btn.pack(fill=tk.X, padx=5, pady=(2, 5))

    def setup_users_panel(self, parent):
        """Kullanıcılar panelini kur"""
        users_frame = tk.Frame(parent, bg=PANEL_BG, relief="raised", bd=1)
        users_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        # Başlık
        tk.Label(users_frame, text="👥 Bağlı Kullanıcılar", 
                bg=PANEL_BG, fg=TEXT_COLOR,
                font=("Segoe UI", 14, "bold")).pack(pady=10)
        
        # Kullanıcı sayısı
        self.user_count_label = tk.Label(users_frame, text="Toplam: 0 kullanıcı",
                                        bg=PANEL_BG, fg="#CCCCCC",
                                        font=("Segoe UI", 10))
        self.user_count_label.pack(pady=(0, 10))
        
        # Kullanıcı listesi
        listbox_frame = tk.Frame(users_frame, bg=PANEL_BG)
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
                                    bg=PANEL_BG, fg=TEXT_COLOR,
                                    font=("Segoe UI", 11, "bold"))
        detail_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.user_detail_text = tk.Text(detail_frame, 
                                       bg=DARK_BG, fg=TEXT_COLOR,
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
                self.update_tcp_status(False)
                self.add_system_message("🛑 TCP sunucu durduruldu")
                
            if self.udp_server:
                self.udp_server.stop()
                self.udp_server = None
                self.update_udp_status(False)
                self.add_system_message("🛑 UDP sunucu durduruldu")
                
            if self.p2p_node:
                self.p2p_node.stop()
                self.p2p_node = None
                self.update_p2p_status(False)
                self.add_system_message("🛑 P2P düğümü durduruldu")
                
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
            self.update_tcp_status(True)
            self.add_system_message(f"✅ TCP sunucu başlatıldı - Kullanıcı: {self.current_username}")
            self.add_system_message("📡 TCP sunucu localhost:12345 adresinde dinliyor")
        except Exception as e:
            raise Exception(f"TCP başlatılamadı: {e}")

    def start_udp_server(self):
        """UDP sunucuyu başlat"""
        try:
            # UDP sunucuyu başlat
            self.udp_server = udp_server.UDPServer()
            self.udp_server_thread = threading.Thread(target=self.udp_server.start, daemon=True)
            self.udp_server_thread.start()
            self.update_udp_status(True)
            self.add_system_message(f"✅ UDP sunucu başlatıldı - Kullanıcı: {self.current_username}")
            self.add_system_message("📡 UDP sunucu localhost:12345 adresinde dinliyor")
        except Exception as e:
            raise Exception(f"UDP başlatılamadı: {e}")

    def start_p2p_node(self):
        """P2P düğümünü başlat"""
        try:
            self.p2p_node = P2PNode(username=self.current_username)
            
            # Mesaj callback'i ayarla
            self.p2p_node.message_callback = self.on_p2p_message_received
            
            self.p2p_node.start()
            self.update_p2p_status(True)
            self.add_system_message(f"✅ P2P düğümü başlatıldı - Kullanıcı: {self.current_username}")
            if hasattr(self.p2p_node, 'host') and hasattr(self.p2p_node, 'port'):
                self.add_system_message(f"📍 Adres: {self.p2p_node.host}:{self.p2p_node.port}")
            
            # Kullanıcı listesini düzenli olarak güncelle
            self.schedule_user_list_update()
            
        except Exception as e:
            raise Exception(f"P2P başlatılamadı: {e}")

    def on_p2p_message_received(self, message: str):
        """P2P'den gelen mesajları chat'e ekle"""
        try:
            # Ana thread'de GUI güncelleme yapılmalı
            self.master.after(0, lambda: self.add_chat_message(message))
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
        color = SUCCESS_COLOR if is_active else ERROR_COLOR
        text = "TCP: Açık" if is_active else "TCP: Kapalı"
        
        self.tcp_indicator.delete("all")
        self.tcp_indicator.create_oval(3, 3, 12, 12, fill=color, outline="#FFFFFF")
        self.tcp_status_label.config(text=text, fg=color)

    def update_udp_status(self, is_active: bool):
        """UDP durum göstergesini güncelle"""
        color = SUCCESS_COLOR if is_active else ERROR_COLOR
        text = "UDP: Açık" if is_active else "UDP: Kapalı"
        
        self.udp_indicator.delete("all")
        self.udp_indicator.create_oval(3, 3, 12, 12, fill=color, outline="#FFFFFF")
        self.udp_status_label.config(text=text, fg=color)

    def update_p2p_status(self, is_active: bool):
        """P2P durum göstergesini güncelle"""
        color = SUCCESS_COLOR if is_active else ERROR_COLOR
        text = "P2P: Açık" if is_active else "P2P: Kapalı"
        
        self.p2p_indicator.delete("all")
        self.p2p_indicator.create_oval(3, 3, 12, 12, fill=color, outline="#FFFFFF")
        self.p2p_status_label.config(text=text, fg=color)

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

    def add_system_message(self, message: str):
        """Sistem mesajı ekle"""
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}"
        
        self.system_display.config(state=tk.NORMAL)
        self.system_display.insert(tk.END, f"{full_message}\n")
        self.system_display.see(tk.END)
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