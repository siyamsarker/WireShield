import threading
import logging
import sqlite3
import time
from app.core.config import AUTH_DB_PATH, WG_INTERFACE

logger = logging.getLogger(__name__)

class DNSSniffer:
    def __init__(self):
        self.interface = WG_INTERFACE or "wg0"
        self.stop_sniffer = threading.Event()
        self.thread = None
        self._db_path = AUTH_DB_PATH
        self.scapy_available = False
        
        try:
            from scapy.all import sniff, DNS, DNSRR
            global sniff, DNS, DNSRR
            self.scapy_available = True
        except ImportError:
            logger.warning("Scapy not found. DNS sniffing disabled.")

    def start(self):
        if not self.scapy_available:
            return
            
        if self.thread and self.thread.is_alive():
            return

        self.stop_sniffer.clear()
        self.thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self.thread.start()
        logger.info(f"DNS Sniffer started on {self.interface}")

    def stop(self):
        if self.thread:
            self.stop_sniffer.set()
            # Sniff is blocking, so we can't easily stop it without timeout or stop_filter
            # Since it's a daemon thread, it will die with the app.
            logger.info("DNS Sniffer stopping...")

    def _run_sniffer(self):
        try:
            # Filter: UDP source port 53 (DNS responses)
            sniff(
                iface=self.interface,
                filter="udp src port 53",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: self.stop_sniffer.is_set()
            )
        except Exception as e:
            logger.error(f"DNS Sniffer failed: {e}")

    def _process_packet(self, pkt):
        if not pkt.haslayer(DNS):
            return

        try:
            dns = pkt[DNS]
            # Only process responses (qr=1) with answers (ancount > 0)
            if dns.qr == 1 and dns.ancount > 0:
                for x in range(dns.ancount):
                    answer = dns.an[x]
                    # Check for A records (type 1)
                    if answer.type == 1:
                        domain = answer.rrname.decode('utf-8').rstrip('.')
                        ip = answer.rdata
                        self._cache_mapping(ip, domain)
        except Exception:
            pass

    def _cache_mapping(self, ip, domain):
        try:
            conn = sqlite3.connect(self._db_path)
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO dns_cache (ip_address, domain, timestamp)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (ip, domain))
            conn.commit()
            conn.close()
        except Exception as e:
            pass # Silent fail to avoid log spam
