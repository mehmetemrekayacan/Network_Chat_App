"""
UDP tabanlı chat istemcisi.
- Çok kullanıcılı, güvenilirlik mekanizmalı UDP chat istemcisi.
- Protokol: network/protocol.py (v1.2)
- Özellikler: pencere yönetimi, paket parçalama, RTT ölçümü, versiyon kontrolü, hata yönetimi.
"""
import socket
import threading
import time
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION, MIN_SUPPORTED_VERSION,
    MAX_PACKET_SIZE, MESSAGE_TYPES, ERROR_CODES, version_compatible,
    fragmenter, window, RETRY_TIMEOUT, MAX_RETRIES
)

server_address = ("localhost", 12345)

def receive_messages(sock):
    """Mesaj alma ve işleme thread'i"""
    while True:
        try:
            data, _ = sock.recvfrom(MAX_PACKET_SIZE)
            packet = parse_packet(data)
            if not packet:
                print("[!] Geçersiz paket alındı")
                continue

            header = packet["header"]
            msg_type = header["type"]
            
            # Hata kodu kontrolü
            if "error_code" in header:
                error_code = header["error_code"]
                if error_code != 0x00:  # Başarılı değilse
                    print(f"[!] Sunucu hatası: {ERROR_CODES.get(error_code, 'Bilinmeyen hata')}")
                    if error_code == 0x02:  # Versiyon uyumsuzluğu
                        print(f"[!] Sunucu protokol versiyonu: {header.get('version', 'Bilinmiyor')}")
                        print(f"[!] İstemci protokol versiyonu: {PROTOCOL_VERSION}")
                        break
                    continue
            
            # RTT ölçümü için pong mesajı
            if msg_type == "pong":
                if "extra" in packet["payload"] and "ping_time" in packet["payload"]["extra"]:
                    sent_time = float(packet["payload"]["extra"]["ping_time"])
                    rtt = (time.time() - sent_time) * 1000
                    print(f"[RTT] Sunucuya gidiş-dönüş süresi: {rtt:.2f} ms")
                continue
            
            # Versiyon kontrolü yanıtı
            if msg_type == "version_check":
                if "extra" in packet["payload"]:
                    extra = packet["payload"]["extra"]
                    server_version = extra.get("server_version", "Bilinmiyor")
                    min_version = extra.get("min_version", "Bilinmiyor")
                    print(f"[*] Sunucu protokol versiyonu: {server_version}")
                    print(f"[*] Minimum desteklenen versiyon: {min_version}")
                continue
            
            # Pencere boyutu güncelleme
            if msg_type == "window_update":
                if "window" in header:
                    window.update_window_size(header["window"])
                    print(f"[*] Sunucu pencere boyutunu güncelledi: {window.window_size}")
                else:
                    print("[*] Sunucudan pencere boyutu güncelleme mesajı alındı.")
                continue
            if "window" in header:
                window.update_window_size(header["window"])
                print(f"[*] Pencere boyutu güncellendi: {window.window_size}")
            
            # ACK işleme
            if msg_type == "ack":
                if "seq" in header:
                    window.mark_acked(header["seq"])
                continue
                
            # Parça işleme
            if "fragment" in header:
                fragment_info = header["fragment"]
                fragment_id = fragment_info["id"]
                fragment_no = fragment_info.get("fragment_no", 0)
                total_fragments = fragment_info["total"]
                
                # Parçayı ekle ve tamamlanıp tamamlanmadığını kontrol et
                complete_data = fragmenter.add_fragment(
                    fragment_id, fragment_no, total_fragments,
                    packet["payload"]["data"]
                )
                # Parça için fragment_ack gönder
                sock.sendto(build_packet(
                    "SERVER", "fragment_ack",
                    extra_payload={
                        "fragment_id": fragment_id,
                        "fragment_no": fragment_no
                    }
                ), server_address)
                
                if complete_data:
                    # Tamamlanan paketi işle
                    packet = parse_packet(complete_data)
                    if not packet:
                        print("[!] Parça birleştirme hatası")
                        continue
                    header = packet["header"]
                    msg_type = header["type"]
                else:
                    # Eksik parça zaman aşımı için fragment_nack gönderme (örnek, gerçek zamanlayıcı ile daha iyi olur)
                    # Burada sadece örnek olarak, eksik parça varsa hemen NACK gönderiyoruz
                    missing = [i for i in range(total_fragments) if i not in fragmenter.fragments.get(fragment_id, {})]
                    if missing:
                        for miss_no in missing:
                            sock.sendto(build_packet(
                                "SERVER", "fragment_nack",
                                extra_payload={
                                    "fragment_id": fragment_id,
                                    "fragment_no": miss_no
                                }
                            ), server_address)
                    continue

            # fragment_ack ve fragment_nack mesajlarını işleme (gönderici için temel altyapı)
            if msg_type == "fragment_ack":
                # Burada, gönderici tarafında parça için ACK alınırsa yeniden gönderim zamanlayıcısı sıfırlanabilir
                # (Gelişmiş dosya transferi için kullanılabilir)
                continue
            if msg_type == "fragment_nack":
                # Burada, gönderici eksik parça için yeniden gönderim yapabilir
                # (Gelişmiş dosya transferi için kullanılabilir)
                print(f"[!] Eksik parça bildirimi alındı: {packet['payload'].get('extra', {})}")
                continue
            
            # --- GELİŞMİŞ SIRALAMA: Sıra numarası olan paketleri buffer'a ekle ---
            if "seq" in header:
                seq = header["seq"]
                window.add_incoming_packet(seq, packet)
                # Sırayla işlenebilecek tüm paketleri sırayla işle
                for in_order_packet in window.get_in_order_packets():
                    _process_incoming_packet(sock, in_order_packet)
                # Bu paket zaten işlenecek, döngüye devam
                continue
            else:
                # Sıra numarası olmayan kontrol paketleri (örn. ping, pong, version_check)
                _process_incoming_packet(sock, packet)
                
        except Exception as e:
            print(f"[!] Mesaj alımında hata: {e}")
            break

def _process_incoming_packet(sock, packet):
    """Sıralı işlenmesi gereken paketlerin işlenmesi (orijinal mesaj işleme kodu buraya taşındı)"""
    header = packet["header"]
    msg_type = header["type"]
    sender = header.get("sender", "?")
    text = packet["payload"].get("text", "")

    # Mesaj tipine göre özel format
    if msg_type == "error":
        print(f"\n[!] Hata: {text}")
    elif msg_type == "join":
        print(f"\n[+] {text}")
    elif msg_type == "leave":
        print(f"\n[-] {text}")
    elif msg_type == "userlist":
        if "extra" in packet["payload"] and "users" in packet["payload"]["extra"]:
            users = packet["payload"]["extra"]["users"]
            print("\n--- Bağlı Kullanıcılar ---")
            for user in users:
                version = user.get("version", "Bilinmiyor")
                print(f"{user['username']} (v{version})")
            print("-------------------------")
    else:
        print(f"\n>> {sender}: {text}")

    # ACK gönder
    if "seq" in header:
        sock.sendto(build_packet(
            "SERVER", "ack",
            seq=header.get("seq"),
            ack=header.get("seq")
        ), server_address)

def fragment_send_with_selective_repeat(sock, fragments, timeout=RETRY_TIMEOUT, max_retries=MAX_RETRIES):
    """Parçaları Selective Repeat ile güvenilir şekilde gönder"""
    fragment_status = {}  # {fragment_no: {"acked": bool, "last_sent": float, "retries": int}}
    fragment_id = None
    total_fragments = len(fragments)
    lock = threading.Lock()

    # fragment_id'yi ilk fragment'tan al
    for frag in fragments:
        frag_packet = parse_packet(frag)
        if frag_packet and "fragment" in frag_packet["header"]:
            fragment_id = frag_packet["header"]["fragment"]["id"]
            break
    if fragment_id is None:
        print("[!] Parça ID bulunamadı!")
        return False

    # Başlangıçta tüm parçaları gönder
    now = time.time()
    for i, frag in enumerate(fragments):
        sock.sendto(frag, server_address)
        fragment_status[i] = {"acked": False, "last_sent": now, "retries": 0}

    def listen_for_acks():
        nonlocal fragment_status
        while True:
            try:
                data, _ = sock.recvfrom(MAX_PACKET_SIZE)
                packet = parse_packet(data)
                if not packet or "header" not in packet:
                    continue
                header = packet["header"]
                msg_type = header["type"]
                if msg_type == "fragment_ack":
                    extra = packet["payload"].get("extra", {})
                    if extra.get("fragment_id") == fragment_id:
                        frag_no = extra.get("fragment_no")
                        with lock:
                            if frag_no in fragment_status:
                                fragment_status[frag_no]["acked"] = True
                elif msg_type == "fragment_nack":
                    extra = packet["payload"].get("extra", {})
                    if extra.get("fragment_id") == fragment_id:
                        frag_no = extra.get("fragment_no")
                        with lock:
                            if frag_no in fragment_status:
                                fragment_status[frag_no]["acked"] = False
                                fragment_status[frag_no]["retries"] += 1
                                fragment_status[frag_no]["last_sent"] = 0  # Hemen tekrar gönderilecek
            except Exception:
                break

    ack_thread = threading.Thread(target=listen_for_acks, daemon=True)
    ack_thread.start()

    start_time = time.time()
    while True:
        all_acked = True
        now = time.time()
        with lock:
            for i, frag in enumerate(fragments):
                status = fragment_status[i]
                if not status["acked"]:
                    all_acked = False
                    # Zaman aşımı veya NACK sonrası tekrar gönder
                    if now - status["last_sent"] > timeout and status["retries"] < max_retries:
                        sock.sendto(frag, server_address)
                        fragment_status[i]["last_sent"] = now
                        fragment_status[i]["retries"] += 1
                    elif status["retries"] >= max_retries:
                        print(f"[X] Parça {i} gönderilemedi (maksimum deneme aşıldı)")
                        return False
        if all_acked:
            return True
        if now - start_time > (timeout * max_retries * total_fragments):
            print("[X] Parça gönderim süresi aşıldı.")
            return False
        time.sleep(0.05)

def send_messages(sock, username):
    """Mesaj gönderme ve yeniden gönderim yönetimi"""
    # Versiyon kontrolü yap
    version_check = build_packet(username, "version_check")
    sock.sendto(version_check, server_address)
    
    # JOIN mesajı gönder
    join_packet = build_packet(username, "join", "katıldı")
    sock.sendto(join_packet, server_address)
    print(f"[*] Protokol v{PROTOCOL_VERSION} ile sunucuya bağlanıldı")
    print(f"[*] Pencere boyutu: {window.window_size}")

    while True:
        try:
            message = input("Sen: ").strip()
            
            # Özel komutlar
            if message.lower() == "rtt":
                # RTT ölçümü için ping gönder
                ping_time = time.time()
                ping_packet = build_packet(
                    username, "ping",
                    extra_payload={"ping_time": str(ping_time)}
                )
                sock.sendto(ping_packet, server_address)
                continue
            elif message.lower() == "version":
                # Versiyon kontrolü
                version_check = build_packet(username, "version_check")
                sock.sendto(version_check, server_address)
                continue
            elif message.lower() == "quit":
                # Çıkış mesajı gönder
                leave_packet = build_packet(username, "leave", "ayrıldı")
                send_with_retry(sock, leave_packet)
                break
                
            if not message:
                continue
                
            # Mesajı paketle
            full_packet = build_packet(username, "message", message)
            
            # Paket boyutu kontrolü ve parçalama
            if len(full_packet) > MAX_PACKET_SIZE:
                print("[*] Mesaj parçalanıyor...")
                fragments = fragmenter.fragment_packet(full_packet)
                if not fragment_send_with_selective_repeat(sock, fragments):
                    print("[!] Mesaj parçaları güvenli şekilde gönderilemedi")
            else:
                if not send_with_retry(sock, full_packet):
                    print("[!] Mesaj gönderilemedi")

        except KeyboardInterrupt:
            # Çıkış mesajı gönder
            try:
                leave_packet = build_packet(username, "leave", "ayrıldı")
                send_with_retry(sock, leave_packet)
            except:
                pass
            break
        except Exception as e:
            print(f"[!] Mesaj gönderme hatası: {e}")

def send_with_retry(sock, packet):
    """Paketi yeniden gönderim mekanizması ile gönder"""
    retries = 0
    while retries < MAX_RETRIES:
        try:
            # Pencere kontrolü
            if not window.can_send():
                print("[!] Pencere dolu, bekleniyor...")
                time.sleep(0.1)
                continue
                
            # Paketi pencereye ekle
            seq = window.add_packet(packet)
            
            # Paketi gönder
            sock.sendto(packet, server_address)
            
            # ACK bekle
            start_time = time.time()
            while time.time() - start_time < RETRY_TIMEOUT:
                try:
                    sock.settimeout(RETRY_TIMEOUT - (time.time() - start_time))
                    data, _ = sock.recvfrom(MAX_PACKET_SIZE)
                    ack_packet = parse_packet(data)
                    
                    if ack_packet and ack_packet["header"]["type"] == "ack":
                        if "seq" in ack_packet["header"] and ack_packet["header"]["seq"] == seq:
                            window.mark_acked(seq)
                            return True
                            
                except socket.timeout:
                    break
                    
            # ACK alınamadı, yeniden dene
            retries += 1
            print(f"[!] ACK alınamadı, tekrar gönderiliyor... ({retries}/{MAX_RETRIES})")
            
        except Exception as e:
            print(f"[!] Gönderme hatası: {e}")
            retries += 1
            
    print("[X] Mesaj gönderilemedi.")
    return False

def start_udp_client():
    """UDP istemciyi başlat"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    username = input("Kullanıcı adınız: ").strip()
    
    if not username:
        print("[!] Geçersiz kullanıcı adı")
        return
        
    print("\nÖzel komutlar:")
    print("- rtt: RTT ölçümü yap")
    print("- version: Protokol versiyonunu kontrol et")
    print("- quit: Sohbetten ayrıl\n")
    
    # Alıcı thread'i başlat
    receiver = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    receiver.start()
    
    try:
        send_messages(sock, username)
    finally:
        sock.close()

if __name__ == "__main__":
    start_udp_client()
