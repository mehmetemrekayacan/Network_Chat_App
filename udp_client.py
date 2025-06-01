"""
UDP tabanlı chat istemcisi.
- Çok kullanıcılı, güvenilirlik mekanizmalı UDP chat istemcisi.
- Protokol: network/protocol.py
- Özellikler: pencere yönetimi, paket parçalama, RTT ölçümü.
"""
import socket
import threading
import time
from datetime import datetime
from protocol import (
    build_packet, parse_packet, PROTOCOL_VERSION, MAX_PACKET_SIZE,
    fragmenter, window, RETRY_TIMEOUT, MAX_RETRIES
)

server_address = ("localhost", 12345)

def receive_messages(sock):
    """Mesaj alma ve işleme thread'i"""
    global last_ping_time
    while True:
        try:
            data, _ = sock.recvfrom(MAX_PACKET_SIZE)
            packet = parse_packet(data)
            if not packet:
                print("[!] Geçersiz paket alındı")
                continue

            header = packet["header"]
            msg_type = header["type"]
            
            # RTT ölçümü için pong mesajı
            if msg_type == "pong":
                if "extra" in packet["payload"] and "ping_time" in packet["payload"]["extra"]:
                    sent_time = float(packet["payload"]["extra"]["ping_time"])
                    rtt = (time.time() - sent_time) * 1000
                    print(f"[RTT] Sunucuya gidiş-dönüş süresi: {rtt:.2f} ms")
                continue
            
            # Pencere boyutu güncelleme
            if "window" in header:
                window.update_window_size(header["window"])
            
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
                
                if complete_data:
                    # Tamamlanan paketi işle
                    packet = parse_packet(complete_data)
                    if not packet:
                        continue
                    header = packet["header"]
                    msg_type = header["type"]
                else:
                    # Parça için ACK gönder
                    sock.sendto(build_packet(
                        "SERVER", "ack",
                        seq=header.get("seq"),
                        ack=header.get("seq")
                    ), server_address)
                    continue
            
            # Normal mesaj işleme
            sender = header["sender"]
            text = packet["payload"]["text"]
            
            # Mesaj tipine göre özel format
            if msg_type == "error":
                print(f"\n[!] Hata: {text}")
            elif msg_type == "join":
                print(f"\n[+] {text}")
            elif msg_type == "leave":
                print(f"\n[-] {text}")
            else:
                print(f"\n>> {sender}: {text}")
                
            # ACK gönder
            if "seq" in header:
                sock.sendto(build_packet(
                    "SERVER", "ack",
                    seq=header.get("seq"),
                    ack=header.get("seq")
                ), server_address)
                
        except Exception as e:
            print(f"[!] Mesaj alımında hata: {e}")
            break

def send_messages(sock, username):
    """Mesaj gönderme ve yeniden gönderim yönetimi"""
    # JOIN mesajı gönder
    join_packet = build_packet(username, "join", "katıldı")
    sock.sendto(join_packet, server_address)
    print(f"[*] Protokol v{PROTOCOL_VERSION} ile sunucuya bağlanıldı")
    print(f"[*] Pencere boyutu: {window.window_size}")

    while True:
        try:
            message = input("Sen: ")
            if message.strip().lower() == "rtt":
                # RTT ölçümü için ping gönder
                ping_time = time.time()
                ping_packet = build_packet(username, "ping", extra_payload={"ping_time": str(ping_time)})
                sock.sendto(ping_packet, server_address)
                continue
            if not message.strip():
                continue
                
            # Mesajı paketle
            full_packet = build_packet(username, "message", message)
            
            # Paket boyutu kontrolü ve parçalama
            if len(full_packet) > MAX_PACKET_SIZE:
                fragments = fragmenter.fragment_packet(full_packet)
                for fragment in fragments:
                    send_with_retry(sock, fragment)
            else:
                send_with_retry(sock, full_packet)

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
    username = input("Kullanıcı adınız: ")
    
    # Alıcı thread'i başlat
    receiver = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    receiver.start()
    
    try:
        send_messages(sock, username)
    finally:
        sock.close()

if __name__ == "__main__":
    start_udp_client()
