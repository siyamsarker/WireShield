"""Tests for UTC timestamp normalization in the activity log ingestion pipeline.

The normalization logic lives in tasks._ingest_activity_logs. We extract and
test it in isolation to avoid needing journalctl or a running event loop.
"""
import os
import sys
import re
from pathlib import Path

import pytest

os.environ.setdefault("WS_2FA_SECRET_KEY", "wireshield-test-secret-key")
service_root = Path(__file__).parent.parent / "console-server"
if str(service_root) not in sys.path:
    sys.path.insert(0, str(service_root))


def _normalize_ts(ts_raw: str) -> str:
    """Exact copy of the normalization block in tasks._ingest_activity_logs."""
    from datetime import datetime, timezone
    ts = ts_raw
    try:
        if 'T' in ts_raw:
            dt = datetime.fromisoformat(ts_raw.replace('Z', '+00:00'))
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            ts = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return ts


def _parse_log_fields(msg: str):
    """Exact copy of the regex extraction block in tasks._ingest_activity_logs."""
    direction = None
    protocol = None
    src_ip = None
    src_port = None
    dst_ip = None
    dst_port = None

    in_match = re.search(r'IN=(\S*)', msg)
    out_match = re.search(r'OUT=(\S*)', msg)
    if in_match and in_match.group(1):
        direction = "IN"
    elif out_match and out_match.group(1):
        direction = "OUT"

    src_match = re.search(r'SRC=(\S+)', msg)
    dst_match = re.search(r'DST=(\S+)', msg)
    if src_match:
        src_ip = src_match.group(1)
    if dst_match:
        dst_ip = dst_match.group(1)

    spt_match = re.search(r'SPT=(\d+)', msg)
    dpt_match = re.search(r'DPT=(\d+)', msg)
    if spt_match:
        src_port = spt_match.group(1)
    if dpt_match:
        dst_port = dpt_match.group(1)

    proto_match = re.search(r'PROTO=(\S+)', msg)
    if proto_match:
        protocol = proto_match.group(1)

    return direction, protocol, src_ip, src_port, dst_ip, dst_port


# ---------------------------------------------------------------------------
# UTC normalisation
# ---------------------------------------------------------------------------

class TestUtcNormalization:

    def test_utc_timestamp_unchanged(self):
        assert _normalize_ts("2026-03-29T10:00:00+00:00") == "2026-03-29 10:00:00"

    def test_positive_offset_converted_to_utc(self):
        """UTC+6 16:00 → UTC 10:00."""
        assert _normalize_ts("2026-03-29T16:00:00+06:00") == "2026-03-29 10:00:00"

    def test_negative_offset_converted_to_utc(self):
        """UTC-5 05:00 → UTC 10:00."""
        assert _normalize_ts("2026-03-29T05:00:00-05:00") == "2026-03-29 10:00:00"

    def test_z_suffix_treated_as_utc(self):
        assert _normalize_ts("2026-03-29T10:00:00Z") == "2026-03-29 10:00:00"

    def test_naive_datetime_string_unchanged(self):
        """Space-separated naive datetimes (no 'T') pass through as-is."""
        assert _normalize_ts("2026-03-29 10:00:00") == "2026-03-29 10:00:00"

    def test_iso_without_tz_reformatted_not_shifted(self):
        """ISO datetime without TZ info has no offset to apply."""
        assert _normalize_ts("2026-03-29T10:00:00") == "2026-03-29 10:00:00"

    def test_invalid_timestamp_passes_through(self):
        assert _normalize_ts("garbage-timestamp") == "garbage-timestamp"

    def test_midnight_utc_plus6_wraps_to_previous_day(self):
        """UTC+6 midnight is 18:00 the previous UTC day."""
        # 2026-03-30T00:00:00+06:00 → 2026-03-29T18:00:00Z
        assert _normalize_ts("2026-03-30T00:00:00+06:00") == "2026-03-29 18:00:00"

    def test_half_hour_offset(self):
        """IST (UTC+5:30) 15:30 → UTC 10:00."""
        assert _normalize_ts("2026-03-29T15:30:00+05:30") == "2026-03-29 10:00:00"

    def test_output_format_is_always_space_separated(self):
        result = _normalize_ts("2026-03-29T10:00:00+00:00")
        assert "T" not in result
        assert " " in result


# ---------------------------------------------------------------------------
# WS-Audit log line parser
# ---------------------------------------------------------------------------

class TestActivityLogLineParser:

    def test_outbound_tcp(self):
        line = "[WS-Audit] OUT=wg0 IN= SRC=10.66.66.2 DST=142.250.185.46 PROTO=TCP SPT=54321 DPT=443"
        d, proto, src, spt, dst, dpt = _parse_log_fields(line)
        assert d == "OUT"
        assert proto == "TCP"
        assert src == "10.66.66.2"
        assert dst == "142.250.185.46"
        assert spt == "54321"
        assert dpt == "443"

    def test_inbound_udp(self):
        line = "[WS-Audit] IN=wg0 OUT= SRC=8.8.8.8 DST=10.66.66.2 PROTO=UDP SPT=53 DPT=12345"
        d, proto, src, spt, dst, dpt = _parse_log_fields(line)
        assert d == "IN"
        assert proto == "UDP"
        assert src == "8.8.8.8"
        assert dst == "10.66.66.2"
        assert spt == "53"
        assert dpt == "12345"

    def test_empty_in_and_out_yield_none_direction(self):
        """Both IN= and OUT= empty → no determinable direction."""
        line = "[WS-Audit] IN= OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=ICMP"
        d, proto, src, spt, dst, dpt = _parse_log_fields(line)
        assert d is None

    def test_missing_ports_yield_none(self):
        line = "[WS-Audit] OUT=wg0 IN= SRC=10.0.0.1 DST=1.1.1.1 PROTO=ICMP"
        d, proto, src, spt, dst, dpt = _parse_log_fields(line)
        assert spt is None
        assert dpt is None

    def test_missing_proto_yields_none(self):
        line = "[WS-Audit] OUT=wg0 IN= SRC=10.0.0.1 DST=1.1.1.1"
        d, proto, src, spt, dst, dpt = _parse_log_fields(line)
        assert proto is None

    def test_in_takes_priority_over_out_when_both_nonempty(self):
        """When both IN and OUT have values, IN is checked first → 'IN'."""
        line = "[WS-Audit] IN=eth0 OUT=wg0 SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP"
        d, *_ = _parse_log_fields(line)
        assert d == "IN"

    def test_ipv6_addresses_parsed(self):
        line = "[WS-Audit] OUT=wg0 IN= SRC=fd86:ea04::2 DST=2001:db8::1 PROTO=TCP SPT=443 DPT=8080"
        d, proto, src, spt, dst, dpt = _parse_log_fields(line)
        assert src == "fd86:ea04::2"
        assert dst == "2001:db8::1"


# ---------------------------------------------------------------------------
# Integration: normalization + ingestion DB write
# ---------------------------------------------------------------------------

def test_utc_timestamp_stored_in_db(tmp_db):
    """Timestamps ingested with a TZ offset must be stored as UTC in the DB."""
    from app.core import database

    conn = database.get_db()
    # UTC+6 16:00:00 → UTC 10:00:00
    ts = _normalize_ts("2026-03-29T16:00:00+06:00")
    conn.execute(
        "INSERT INTO activity_log "
        "(timestamp, client_id, direction, protocol, src_ip, src_port, "
        "dst_ip, dst_port, raw_line, line_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, "alice", "OUT", "TCP", "10.66.66.2", "443", "1.1.1.1", "80",
         "[WS-Audit] test", "hash-utc-test"),
    )
    conn.commit()

    row = conn.execute(
        "SELECT timestamp FROM activity_log WHERE line_hash = 'hash-utc-test'"
    ).fetchone()
    conn.close()
    assert row[0] == "2026-03-29 10:00:00"
