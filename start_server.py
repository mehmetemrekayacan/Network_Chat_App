import threading
import time
import logging
import server
import udp_server
import topology_discovery

# Logging ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    """
    TCP ve UDP sunucularını ve topoloji keşif hizmetini başlatır.
    """
    TCP_PORT = 12345
    UDP_PORT = 12346
    SERVER_PEER_ID = "SERVER_NODE"

    logging.info("--- Sohbet Sunucusu Başlatılıyor ---")

    udp_server_instance = None  # finally bloğunda erişim için

    try:
        # TCP genel sohbet sunucusunu ayrı bir thread'de başlat
        tcp_server_thread = threading.Thread(
            target=server.start_server_with_port,
            args=(TCP_PORT,),
            daemon=True
        )
        tcp_server_thread.start()
        logging.info(f"TCP Sunucu thread'i {TCP_PORT} portunda başlatıldı.")

        # UDP özel mesaj sunucusunu ayrı bir thread'de başlat
        udp_server_instance = udp_server.UDPServer(port=UDP_PORT)
        udp_server_thread = threading.Thread(
            target=udp_server_instance.start,
            daemon=True
        )
        udp_server_thread.start()
        logging.info(f"UDP Sunucu thread'i {UDP_PORT} portunda başlatıldı.")

        # Sunucunun kendisi için ağ topoloji keşif hizmetini başlat
        topology_discovery.topology_discovery.start_discovery(SERVER_PEER_ID)
        logging.info(f"Topoloji Keşif hizmeti '{SERVER_PEER_ID}' kimliği ile başlatıldı.")
        
        logging.info("--- Sunucu başarıyla çalışıyor ---")
        # Ana thread'i canlı tutarak daemon thread'lerin çalışmasını sağla
        while True:
            time.sleep(3600) # Periyodik görevler için uyku

    except Exception as e:
        logging.critical(f"Kritik bir hata oluştu: {e}")
    finally:
        logging.info("--- Sunucu kapatılıyor ---")
        server.stop_server()
        if udp_server_instance:
            udp_server_instance.stop()
        topology_discovery.topology_discovery.stop_discovery()
        logging.info("--- Sunucu kapatma işlemi tamamlandı ---")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKullanıcı tarafından sunucuyu kapatma isteği alındı.") 