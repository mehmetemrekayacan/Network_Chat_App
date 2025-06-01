import socket
import threading
import json
from datetime import datetime

username = input("Kullanıcı adınız: ")

def build_packet(msg_type, text=""):
    return json.dumps({
        "header": {
            "type": msg_type,
            "timestamp": datetime.now().isoformat(),
            "sender": username
        },
        "payload": {
            "text": text
        }
    }).encode()

def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            try:
                packet = json.loads(data.decode())
                msg_type = packet["header"]["type"]
                if msg_type == "userlist":
                    users = packet["payload"].get("users", [])
                    print("\n--- Bağlı Kullanıcılar ---")
                    for user in users:
                        print(f"{user['username']} ({user['ip']})")
                    print("-------------------------")
                    continue
                sender = packet["header"]["sender"]
                text = packet["payload"]["text"]
                print(f"\n>> {sender}: {text}")
            except Exception as e:
                print("[!] Mesaj çözümlemede hata:", e)
        except:
            print("Bağlantı kesildi.")
            break

def send_messages(sock):
    # JOIN mesajı gönder
    sock.send(build_packet("join", "katıldı"))
    while True:
        message = input("Sen: ")
        sock.send(build_packet("message", message))

def start_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 12345))  # Sunucu IP ve port
    print(">> Sunucuya bağlandın.")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
    send_messages(sock)

start_client()
