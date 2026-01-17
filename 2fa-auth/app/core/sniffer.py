import threading
import logging
import sqlite3
import time
from importlib import import_module
from typing import Optional, TYPE_CHECKING, Any
from app.core.config import AUTH_DB_PATH, WG_INTERFACE

if TYPE_CHECKING:
    from scapy.all import sniff as scapy_sniff
    from scapy.layers.dns import DNS as ScapyDNS, DNSRR as ScapyDNSRR

logger = logging.getLogger(__name__)

class DNSSniffer:
    def __init__(self):
        self.interface = WG_INTERFACE or "wg0"
        self.stop_sniffer = threading.Event()
        self.thread = None
        self._db_path = AUTH_DB_PATH
        self.scapy_available = False
        self._sniff = None
        self._DNS = None
        self._DNSRR = None
        
        try:
            scapy_all = import_module("scapy.all")
            self._sniff = getattr(scapy_all, "sniff", None)
            self._DNS = getattr(scapy_all, "DNS", None)
            self._DNSRR = getattr(scapy_all, "DNSRR", None)
            self.scapy_available = all([self._sniff, self._DNS, self._DNSRR])
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
            if not self._sniff:
                return
            # Filter: UDP source port 53 (DNS responses)
            self._sniff(
                iface=self.interface,
                filter="udp src port 53",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: self.stop_sniffer.is_set()
            )
        except Exception as e:
            logger.error(f"DNS Sniffer failed: {e}")

    def _process_packet(self, pkt):
        if not self._DNS:
            return
        if not pkt.haslayer(self._DNS):
            return

        try:
            dns = pkt[self._DNS]
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
