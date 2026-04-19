import threading
import logging
import sqlite3
from importlib import import_module
from typing import Optional
from app.core.config import AUTH_DB_PATH, WG_INTERFACE

logger = logging.getLogger(__name__)

class DNSSniffer:
    """Captures DNS responses (UDP 53) and TLS ClientHello SNI (TCP 443)
    on the WireGuard interface to build an IP → domain cache.

    TLS SNI extraction is critical because modern browsers use DNS-over-HTTPS,
    which completely bypasses traditional DNS sniffing. The SNI field in the
    TLS ClientHello is still plaintext in TLS 1.2 and most TLS 1.3 connections,
    giving us the real domain name for every HTTPS connection.
    """
    def __init__(self):
        self.interface = WG_INTERFACE or "wg0"
        self.stop_sniffer = threading.Event()
        self.thread = None
        self._db_path = AUTH_DB_PATH
        self.scapy_available = False
        self._sniff = None
        self._DNS = None
        self._DNSRR = None
        self._TCP = None
        self._Raw = None

        try:
            scapy_all = import_module("scapy.all")
            self._sniff = getattr(scapy_all, "sniff", None)
            self._DNS = getattr(scapy_all, "DNS", None)
            self._DNSRR = getattr(scapy_all, "DNSRR", None)
            self._TCP = getattr(scapy_all, "TCP", None)
            self._Raw = getattr(scapy_all, "Raw", None)
            self._IP = getattr(scapy_all, "IP", None)
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
        logger.info(f"DNS + TLS SNI sniffer started on {self.interface}")

    def stop(self):
        if self.thread:
            self.stop_sniffer.set()
            logger.info("DNS + TLS SNI sniffer stopping...")

    def is_alive(self) -> bool:
        """Report whether the sniffer thread is currently running."""
        return bool(self.thread and self.thread.is_alive())

    def _is_interface_up(self) -> bool:
        """Check /sys/class/net/<iface>/operstate. Returns False if iface missing."""
        try:
            with open(f"/sys/class/net/{self.interface}/operstate", "r") as f:
                state = f.read().strip()
            return state in ("up", "unknown")
        except (FileNotFoundError, PermissionError, OSError):
            return False

    def _run_sniffer(self):
        """Robust sniffer loop: auto-recovers from interface flaps and transient errors.

        The previous implementation would exit the thread on the first exception,
        leaving the sniffer permanently dead after any wg0 down event. This loop
        continuously restarts the sniff() call with exponential backoff, waits
        for the interface to come back up before retrying, and survives any
        kind of transient error.
        """
        if not self._sniff:
            return

        backoff = 2.0
        max_backoff = 60.0
        last_log_state = None  # avoid log spam

        while not self.stop_sniffer.is_set():
            # Wait for interface to be up before attempting sniff
            if not self._is_interface_up():
                if last_log_state != "down":
                    logger.warning(f"Interface {self.interface} is down — waiting for it to come back up")
                    last_log_state = "down"
                # Poll every 5s; exit loop promptly on stop signal
                if self.stop_sniffer.wait(5.0):
                    break
                continue

            if last_log_state == "down":
                logger.info(f"Interface {self.interface} is back up — resuming sniff")
                backoff = 2.0  # reset backoff after successful recovery
            last_log_state = "up"

            try:
                # store=0 prevents memory growth; timeout=300 so we periodically
                # re-check the interface state and catch silent socket death.
                self._sniff(
                    iface=self.interface,
                    filter="udp src port 53 or tcp dst port 443",
                    prn=self._process_packet,
                    store=0,
                    stop_filter=lambda x: self.stop_sniffer.is_set(),
                    timeout=300,
                )
                # sniff() returned normally (timeout or stop_filter). Loop and re-check.
                backoff = 2.0
            except OSError as e:
                # errno 100 = ENETDOWN (interface went down mid-sniff)
                # errno 19 = ENODEV (device removed)
                if e.errno in (100, 19):
                    logger.warning(f"{self.interface} dropped during sniff (errno={e.errno}), will retry")
                    last_log_state = "down"
                else:
                    logger.error(f"Sniffer OSError (errno={e.errno}): {e}")
                if self.stop_sniffer.wait(backoff):
                    break
                backoff = min(backoff * 2, max_backoff)
            except Exception as e:
                logger.error(f"Sniffer error (will retry in {backoff}s): {e}")
                if self.stop_sniffer.wait(backoff):
                    break
                backoff = min(backoff * 2, max_backoff)

        logger.info("DNS + TLS SNI sniffer loop exited cleanly")

    def _process_packet(self, pkt):
        try:
            # DNS response handling
            if self._DNS and pkt.haslayer(self._DNS):
                self._handle_dns(pkt)
                return

            # TLS ClientHello SNI extraction (TCP dst port 443 with payload)
            if self._TCP and self._Raw and pkt.haslayer(self._TCP) and pkt.haslayer(self._Raw):
                tcp_layer = pkt[self._TCP]
                if tcp_layer.dport == 443:
                    self._handle_tls(pkt)
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    # ── DNS Response Handler ────────────────────────────────────────────────

    def _handle_dns(self, pkt):
        dns = pkt[self._DNS]
        if dns.qr != 1 or dns.ancount <= 0:
            return

        queried_domain = None
        if dns.qdcount > 0 and dns.qd:
            qname = dns.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode('utf-8', errors='ignore')
            queried_domain = qname.rstrip('.')

        if not queried_domain:
            return

        for x in range(dns.ancount):
            answer = dns.an[x]
            if answer.type in (1, 28):  # A or AAAA
                ip = answer.rdata
                if ip:
                    self._cache_mapping(ip, queried_domain)

    # ── TLS ClientHello SNI Handler ─────────────────────────────────────────

    def _handle_tls(self, pkt):
        raw = bytes(pkt[self._Raw])
        sni = _extract_sni(raw)
        if not sni:
            return

        # Get destination IP from IP layer
        dst_ip = None
        if self._IP and pkt.haslayer(self._IP):
            dst_ip = pkt[self._IP].dst

        if dst_ip and sni:
            self._cache_mapping(dst_ip, sni)
            logger.debug(f"TLS SNI: {dst_ip} → {sni}")

    # ── DNS Cache ───────────────────────────────────────────────────────────

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
            logger.debug(f"DNS cache update failed for {ip} -> {domain}: {e}")


# ── TLS SNI Parser ──────────────────────────────────────────────────────────

def _extract_sni(payload: bytes) -> Optional[str]:
    """Extract the Server Name Indication from a TLS ClientHello packet.

    Parses the raw TCP payload to find the SNI extension (type 0x0000) in
    the TLS handshake. Works for TLS 1.2 and TLS 1.3 ClientHello messages.
    Returns the domain string or None if not found / not a ClientHello.
    """
    try:
        # Need at least TLS record header (5 bytes) + handshake type (1)
        if len(payload) < 6:
            return None

        # TLS Record: content_type=0x16 (Handshake), version=0x0301-0x0303
        if payload[0] != 0x16:
            return None
        if payload[1] != 0x03 or payload[2] not in (0x00, 0x01, 0x02, 0x03):
            return None

        # Handshake record starts at offset 5: type(1) + length(3)
        hs_type = payload[5]
        if hs_type != 0x01:  # ClientHello
            return None

        # ClientHello body starts at offset 9:
        # version(2) + random(32) = 34 bytes
        pos = 9 + 34  # = 43

        if pos >= len(payload):
            return None

        # Session ID: length(1) + data
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 > len(payload):
            return None

        # Cipher Suites: length(2) + data
        cs_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cs_len

        if pos >= len(payload):
            return None

        # Compression Methods: length(1) + data
        cm_len = payload[pos]
        pos += 1 + cm_len

        if pos + 2 > len(payload):
            return None

        # Extensions: total_length(2) then extension entries
        ext_total = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4

            if ext_type == 0x0000:  # SNI extension
                # SNI list: total_length(2) + entry: type(1) + name_length(2) + name
                if pos + 5 <= len(payload):
                    sn_type = payload[pos + 2]
                    sn_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                    if sn_type == 0 and pos + 5 + sn_len <= len(payload):
                        return payload[pos+5:pos+5+sn_len].decode('ascii')
                return None

            pos += ext_len

    except (IndexError, ValueError, UnicodeDecodeError):
        pass
    return None
