"""
Modern arayüzlü chat uygulaması (Tkinter GUI).
- TCP ve UDP sunucu başlatma/durdurma, kullanıcı yönetimi, mesajlaşma.
- Protokol: network/protocol.py
- Özellikler: çoklu chat odası, kullanıcı listesi, sunucu kontrolü, modern tema.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import importlib.util
import sys
import os

# Sunucu modüllerini dinamik olarak yükle
def load_server_module(module_name):
    module_path = os.path.join(os.path.dirname(__file__), f"{module_name}.py")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

# Sunucu modüllerini yükle
tcp_server = load_server_module("server")
udp_server = load_server_module("udp_server")

# Koyu, mat ve kontrastı düşük modern renkler
BG_COLOR = "#23272e"         # Ana arka plan (füme)
PANEL_BG = "#2e323a"        # Panel arka planı (biraz daha açık füme)
PRIMARY = "#3a4a5a"         # Koyu mavi-gri
SECONDARY = "#36404a"       # Gece yeşili/koyu gri
TEXT_COLOR = "#e0e3e7"      # Açık gri (okunabilir)
CHAT_BG = "#2d3138"         # Chat arka planı (daha açık füme)
ENTRY_BG = "#353a42"        # Input arka planı (daha açık)
BUTTON_BG = "#3a4a5a"       # Koyu mavi-gri
BUTTON_FG = "#e0e3e7"       # Açık gri
INDICATOR_ON = "#4be07b"    # Yeşil
INDICATOR_OFF = "#ff5e5e"   # Kırmızı
USER_ONLINE = "🟢"
USER_OFFLINE = "🔴"
MYTH_CHATS = ["Olimpos", "Valhalla", "Asgard", "Atlantis", "Shambhala"]

class CommonChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Ortak Chat Odası - Modern UI")
        self.master.geometry("900x600")
        self.master.minsize(700, 400)
        self.master.maxsize(900, 600)
        self.master.configure(bg=BG_COLOR)

        self.server_active = False
        self.tcp_server_thread = None
        self.udp_server_thread = None
        self.tcp_server_instance = None  # TCP sunucu nesnesi (gerekirse)
        self.udp_server_instance = None  # UDP sunucu nesnesi
        self.users = []  # (username, online:bool)
        self.system_messages = []  # Sadece sistem olayları
        self.chat_messages = {name: [] for name in MYTH_CHATS}  # chat_ismi: [msg, ...]
        self.active_user = None

        self.setup_ui()

    def setup_ui(self):
        # Üst panel: başlık, sunucu kontrolü ve durum göstergesi
        top = tk.Frame(self.master, bg=BG_COLOR)
        top.pack(fill=tk.X, padx=0, pady=(0, 5))
        
        # Başlık
        tk.Label(top, text="💬 Ortak Chat Odası", font=("Segoe UI", 18, "bold"), 
                bg=BG_COLOR, fg=TEXT_COLOR).pack(side=tk.LEFT, padx=20, pady=10)
        
        # Sunucu durum göstergeleri
        status_frame = tk.Frame(top, bg=BG_COLOR)
        status_frame.pack(side=tk.RIGHT, padx=10)
        
        # TCP Sunucu durumu
        self.tcp_status_indicator = tk.Canvas(status_frame, width=18, height=18, 
                                            bg=BG_COLOR, highlightthickness=0)
        self.tcp_status_indicator.grid(row=0, column=0, padx=(0, 5))
        self.tcp_status_label = tk.Label(status_frame, text="TCP: Kapalı", 
                                       font=("Segoe UI", 11), bg=BG_COLOR, fg=INDICATOR_OFF)
        self.tcp_status_label.grid(row=0, column=1, padx=(0, 15))
        
        # UDP Sunucu durumu
        self.udp_status_indicator = tk.Canvas(status_frame, width=18, height=18, 
                                            bg=BG_COLOR, highlightthickness=0)
        self.udp_status_indicator.grid(row=0, column=2, padx=(0, 5))
        self.udp_status_label = tk.Label(status_frame, text="UDP: Kapalı", 
                                       font=("Segoe UI", 11), bg=BG_COLOR, fg=INDICATOR_OFF)
        self.udp_status_label.grid(row=0, column=3, padx=(0, 15))
        
        # Sunucu kontrol butonları
        button_frame = tk.Frame(top, bg=BG_COLOR)
        button_frame.pack(side=tk.RIGHT, padx=10)
        
        # TCP Sunucu butonları
        self.tcp_start_btn = tk.Button(button_frame, text="TCP Başlat", 
                                     command=self.start_tcp_server,
                                     bg=BUTTON_BG, fg=BUTTON_FG, 
                                     font=("Segoe UI", 10, "bold"),
                                     relief="flat", bd=0,
                                     activebackground=SECONDARY,
                                     activeforeground=TEXT_COLOR)
        self.tcp_start_btn.grid(row=0, column=0, padx=(0, 5))
        
        self.tcp_stop_btn = tk.Button(button_frame, text="TCP Durdur",
                                    command=self.stop_tcp_server,
                                    bg=SECONDARY, fg=BUTTON_FG,
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat", bd=0,
                                    state=tk.DISABLED,
                                    activebackground=PRIMARY,
                                    activeforeground=TEXT_COLOR)
        self.tcp_stop_btn.grid(row=0, column=1, padx=(0, 15))
        
        # UDP Sunucu butonları
        self.udp_start_btn = tk.Button(button_frame, text="UDP Başlat",
                                     command=self.start_udp_server,
                                     bg=BUTTON_BG, fg=BUTTON_FG,
                                     font=("Segoe UI", 10, "bold"),
                                     relief="flat", bd=0,
                                     activebackground=SECONDARY,
                                     activeforeground=TEXT_COLOR)
        self.udp_start_btn.grid(row=0, column=2, padx=(0, 5))
        
        self.udp_stop_btn = tk.Button(button_frame, text="UDP Durdur",
                                    command=self.stop_udp_server,
                                    bg=SECONDARY, fg=BUTTON_FG,
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat", bd=0,
                                    state=tk.DISABLED,
                                    activebackground=PRIMARY,
                                    activeforeground=TEXT_COLOR)
        self.udp_stop_btn.grid(row=0, column=3)

        # Ana alan: kullanıcılar ve chat
        main = tk.Frame(self.master, bg=BG_COLOR)
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        # Kullanıcılar paneli
        user_panel = tk.Frame(main, bg=PANEL_BG)
        user_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20), pady=0)
        user_panel.grid_rowconfigure(0, weight=1)
        user_panel.grid_rowconfigure(1, weight=0)
        user_panel.grid_columnconfigure(0, weight=1)
        tk.Label(user_panel, text="Kullanıcılar", bg=PANEL_BG, fg=TEXT_COLOR, font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.user_listbox = tk.Listbox(user_panel, bg=ENTRY_BG, fg=TEXT_COLOR, font=("Segoe UI", 11), relief="flat", selectbackground=PRIMARY, selectforeground=TEXT_COLOR, activestyle='none', width=22, height=20, borderwidth=0, highlightthickness=0)
        self.user_listbox.grid(row=1, column=0, sticky="nsew")
        self.user_listbox.bind("<<ListboxSelect>>", self.on_user_select)
        # Kullanıcı ekleme - panelin en altına sabit, sabit yükseklikte ve belirgin kutu
        add_frame = tk.Frame(user_panel, bg="#23272e", bd=0, highlightbackground="#444", highlightthickness=1, height=80)
        add_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        add_frame.grid_propagate(False)
        tk.Label(add_frame, text="Kullanıcı Bağla", bg="#23272e", fg=TEXT_COLOR, font=("Segoe UI", 11, "bold")).pack(side=tk.TOP, anchor="w", padx=10, pady=(8, 2))
        entry_row = tk.Frame(add_frame, bg="#23272e")
        entry_row.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.username_entry = tk.Entry(entry_row, width=14, font=("Segoe UI", 11), bg=ENTRY_BG, fg=TEXT_COLOR, relief="flat", insertbackground=TEXT_COLOR)
        self.username_entry.pack(side=tk.LEFT, padx=(0, 8), fill=tk.X, expand=True)
        self.add_user_btn = tk.Button(entry_row, text="Bağlan", command=self.add_user, bg=BUTTON_BG, fg=BUTTON_FG, font=("Segoe UI", 10, "bold"), relief="flat", bd=0, activebackground=SECONDARY, activeforeground=TEXT_COLOR)
        self.add_user_btn.pack(side=tk.LEFT)

        # Chat paneli - sekmeli yapı
        chat_panel = tk.Frame(main, bg=BG_COLOR)
        chat_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.notebook = ttk.Notebook(chat_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=0, pady=(0, 10))
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook.Tab', background=CHAT_BG, font=("Segoe UI", 11), padding=[16, 8], foreground=TEXT_COLOR)
        style.map('TNotebook.Tab', background=[('selected', ENTRY_BG)])
        style.configure('TNotebook', background=BG_COLOR, borderwidth=0)
        # Sistem sekmesi
        self.system_tab = tk.Frame(self.notebook, bg=CHAT_BG)
        self.system_chat = tk.Text(self.system_tab, state='disabled', width=60, height=20, bg=CHAT_BG, fg=TEXT_COLOR, font=("Segoe UI", 11), relief="flat", wrap="word", borderwidth=0, highlightthickness=0)
        self.system_chat.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.notebook.add(self.system_tab, text="Sistem")
        # Mitolojik chat sekmeleri
        self.chat_areas = {}
        for chat_name in MYTH_CHATS:
            tab = tk.Frame(self.notebook, bg=CHAT_BG)
            chat_area = tk.Text(tab, state='disabled', width=60, height=20, bg=CHAT_BG, fg=TEXT_COLOR, font=("Segoe UI", 11), relief="flat", wrap="word", borderwidth=0, highlightthickness=0)
            chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            self.notebook.add(tab, text=chat_name)
            self.chat_areas[chat_name] = chat_area
        # Mesaj kutusu (tüm sekmeler için ortak)
        bottom = tk.Frame(chat_panel, bg=BG_COLOR)
        bottom.pack(fill=tk.X, padx=0, pady=(0, 10))
        entry_box = tk.Frame(bottom, bg=ENTRY_BG, bd=0, highlightbackground="#444", highlightthickness=1)
        entry_box.pack(fill=tk.X, padx=0, pady=0)
        self.message_entry = tk.Entry(entry_box, width=50, font=("Segoe UI", 11), bg=ENTRY_BG, fg=TEXT_COLOR, relief="flat", insertbackground=TEXT_COLOR, borderwidth=0)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10), pady=8)
        self.send_btn = tk.Button(entry_box, text="Gönder", command=self.send_message, bg=BUTTON_BG, fg=BUTTON_FG, font=("Segoe UI", 10, "bold"), relief="flat", bd=0, activebackground=SECONDARY, activeforeground=TEXT_COLOR)
        self.send_btn.pack(side=tk.LEFT, padx=(0, 10), pady=8)
        self.message_entry.bind("<Return>", lambda e: self.send_message())

    def draw_server_indicator(self, canvas, active, is_tcp=True):
        canvas.delete("all")
        color = INDICATOR_ON if active else INDICATOR_OFF
        canvas.create_oval(2, 2, 16, 16, fill=color, outline=color)
        label = self.tcp_status_label if is_tcp else self.udp_status_label
        label.config(text=f"{'TCP' if is_tcp else 'UDP'}: {'Açık' if active else 'Kapalı'}", 
                    fg=INDICATOR_ON if active else INDICATOR_OFF)

    def update_server_active(self):
        # En az bir sunucu thread'i çalışıyorsa aktif kabul et
        tcp_alive = self.tcp_server_thread and self.tcp_server_thread.is_alive()
        udp_alive = self.udp_server_thread and self.udp_server_thread.is_alive()
        self.server_active = tcp_alive or udp_alive
        # Mesaj gönderme alanlarını sunucu durumuna göre aktif/pasif yap
        if self.server_active:
            self.send_btn.config(state=tk.NORMAL)
            self.message_entry.config(state=tk.NORMAL)
        else:
            self.send_btn.config(state=tk.DISABLED)
            self.message_entry.config(state=tk.DISABLED)
        # Sadece bir sunucu aynı anda çalışabilir
        if tcp_alive:
            self.udp_start_btn.config(state=tk.DISABLED)
            self.tcp_start_btn.config(state=tk.DISABLED)
            self.udp_stop_btn.config(state=tk.NORMAL)
            self.tcp_stop_btn.config(state=tk.NORMAL)
        elif udp_alive:
            self.tcp_start_btn.config(state=tk.DISABLED)
            self.udp_start_btn.config(state=tk.DISABLED)
            self.tcp_stop_btn.config(state=tk.NORMAL)
            self.udp_stop_btn.config(state=tk.NORMAL)
        else:
            self.tcp_start_btn.config(state=tk.NORMAL)
            self.udp_start_btn.config(state=tk.NORMAL)
            self.tcp_stop_btn.config(state=tk.DISABLED)
            self.udp_stop_btn.config(state=tk.DISABLED)

    def start_tcp_server(self):
        self.update_server_active()
        if self.tcp_server_thread and self.tcp_server_thread.is_alive():
            messagebox.showwarning("Uyarı", "TCP sunucu zaten çalışıyor!")
            return
        if self.udp_server_thread and self.udp_server_thread.is_alive():
            messagebox.showwarning("Uyarı", "Önce UDP sunucuyu kapatmalısınız!")
            return
        try:
            self.tcp_server_thread = threading.Thread(target=tcp_server.start_server, daemon=True)
            self.tcp_server_thread.start()
            self.draw_server_indicator(self.tcp_status_indicator, True, True)
            self.system_messages.append("☑ TCP sunucu başlatıldı.")
            self.update_system_chat()
            self.update_server_active()
        except Exception as e:
            messagebox.showerror("Hata", f"TCP sunucu başlatılamadı: {e}")

    def start_udp_server(self):
        self.update_server_active()
        if self.udp_server_thread and self.udp_server_thread.is_alive():
            messagebox.showwarning("Uyarı", "UDP sunucu zaten çalışıyor!")
            return
        if self.tcp_server_thread and self.tcp_server_thread.is_alive():
            messagebox.showwarning("Uyarı", "Önce TCP sunucuyu kapatmalısınız!")
            return
        try:
            self.udp_server_instance = udp_server.UDPServer()
            self.udp_server_thread = threading.Thread(target=self.udp_server_instance.start, daemon=True)
            self.udp_server_thread.start()
            self.draw_server_indicator(self.udp_status_indicator, True, False)
            self.system_messages.append("☑ UDP sunucu başlatıldı.")
            self.update_system_chat()
            self.update_server_active()
        except Exception as e:
            messagebox.showerror("Hata", f"UDP sunucu başlatılamadı: {e}")

    def stop_tcp_server(self):
        if not self.tcp_server_thread or not self.tcp_server_thread.is_alive():
            messagebox.showwarning("Uyarı", "TCP sunucu zaten kapalı!")
            return
        try:
            # Asıl TCP sunucuyu durdur
            tcp_server.stop_server()
            self.draw_server_indicator(self.tcp_status_indicator, False, True)
            self.system_messages.append("🛑 TCP sunucu durduruldu.")
            self.update_system_chat()
            self.update_server_active()
        except Exception as e:
            messagebox.showerror("Hata", f"TCP sunucu durdurulamadı: {e}")

    def stop_udp_server(self):
        if not self.udp_server_thread or not self.udp_server_thread.is_alive():
            messagebox.showwarning("Uyarı", "UDP sunucu zaten kapalı!")
            return
        try:
            if self.udp_server_instance:
                self.udp_server_instance.stop()
            self.draw_server_indicator(self.udp_status_indicator, False, False)
            self.system_messages.append("🛑 UDP sunucu durduruldu.")
            self.update_system_chat()
            self.update_server_active()
        except Exception as e:
            messagebox.showerror("Hata", f"UDP sunucu durdurulamadı: {e}")

    def add_user(self):
        self.update_server_active()  # Sunucu durumu güncel olsun
        if not self.server_active:
            messagebox.showerror("Sunucu Kapalı", "Sunucu kapalıyken kullanıcı eklenemez!")
            return
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Hata", "Kullanıcı adı zorunlu!")
            return
        if any(u[0] == username for u in self.users):
            messagebox.showerror("Hata", "Bu kullanıcı zaten ekli!")
            return
        self.users.append((username, True))
        self.update_user_list()
        self.username_entry.delete(0, tk.END)
        self.active_user = username
        # Sistem sekmesine mesaj
        self.system_messages.append(f"👤 {username} bağlandı.")
        self.update_system_chat()

    def on_user_select(self, event):
        selection = self.user_listbox.curselection()
        if selection:
            username = self.user_listbox.get(selection[0])
            username = username.split(' ', 1)[1]
            self.active_user = username
            # İlgili chat sekmesine geç
            for i in range(self.notebook.index('end')):
                if self.notebook.tab(i, 'text') == username:
                    self.notebook.select(i)
                    break

    def send_message(self):
        self.update_server_active()
        if not self.server_active:
            messagebox.showerror("Sunucu Kapalı", "Sunucu kapalıyken mesaj gönderilemez!")
            return
        message = self.message_entry.get().strip()
        if not message or not self.active_user:
            return
        tab_idx = self.notebook.index(self.notebook.select())
        tab_name = self.notebook.tab(tab_idx, 'text')
        if tab_name == "Sistem":
            messagebox.showinfo("Bilgi", "Sistem sekmesinde mesaj gönderilemez.")
            return
        chat_area = self.chat_areas.get(tab_name)
        if chat_area:
            chat_area.config(state='normal')
            chat_area.insert(tk.END, f"{self.active_user}: {message}\n")
            chat_area.config(state='disabled')
            chat_area.yview(tk.END)
            self.chat_messages[tab_name].append(f"{self.active_user}: {message}")
        self.message_entry.delete(0, tk.END)

    def update_system_chat(self):
        self.system_chat.config(state='normal')
        self.system_chat.delete(1.0, tk.END)
        for msg in self.system_messages:
            self.system_chat.insert(tk.END, f"{msg}\n")
        self.system_chat.config(state='disabled')
        self.system_chat.yview(tk.END)

    def update_user_list(self):
        self.user_listbox.delete(0, tk.END)
        for username, online in self.users:
            icon = USER_ONLINE if online else USER_OFFLINE
            self.user_listbox.insert(tk.END, f"{icon} {username}")

    def on_closing(self):
        """Uygulama kapatılırken sunucuları düzgün şekilde kapat"""
        if self.tcp_server_thread and self.tcp_server_thread.is_alive():
            self.stop_tcp_server()
        if self.udp_server_thread and self.udp_server_thread.is_alive():
            self.stop_udp_server()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CommonChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop() 