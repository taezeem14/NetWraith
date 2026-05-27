"""
NetWraith – DNS Sniffer Engine
===============================

Captures DNS traffic on UDP port 53, parses queries and responses, and
performs lightweight anomaly detection:

* **DNS_TUNNELING** – any label in the queried domain exceeds 50 characters.
* **HIGH_QUERY_RATE** – a single source IP sends > 50 queries in a
  10-second rolling window.
"""

import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import DNS, DNSQR, DNSRR, IP, sniff  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# Query-type int → human-readable label
_QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

_RATE_WINDOW_SECONDS = 10
_RATE_THRESHOLD = 50
_TUNNEL_LABEL_LEN = 50


class DNSSnifferThread(QThread):
    """
    QThread that sniffs DNS packets and detects anomalies.

    Signals
    -------
    dns_query : dict
        Emitted for every observed DNS transaction.
    dns_anomaly : dict
        Emitted when a suspicious pattern is detected.
    error_signal : str
        Emitted on unrecoverable error.
    """

    dns_query = pyqtSignal(dict)
    dns_anomaly = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, iface: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.iface = iface
        self._stop_flag = False

        # Per-source sliding-window query timestamps
        self._query_times: dict[str, deque] = defaultdict(deque)

        # Track request timestamps for latency estimation (txid → mono time)
        self._pending_queries: dict[int, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request sniff loop to stop."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # QThread entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            kwargs: dict = {
                "filter": "udp port 53",
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _pkt: self._stop_flag,
            }
            if self.iface:
                kwargs["iface"] = self.iface

            logger.info("DNS sniffer started on iface=%s", self.iface)
            sniff(**kwargs)
            logger.info("DNS sniffer stopped.")
        except Exception as exc:
            logger.exception("DNS sniffer error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------
    def _process_packet(self, pkt) -> None:  # noqa: C901
        if self._stop_flag:
            return

        if not pkt.haslayer(DNS):
            return

        dns_layer = pkt[DNS]
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        now_mono = time.monotonic()
        now_iso = datetime.now(timezone.utc).isoformat()

        # ------- DNS QUERY (qr == 0) -------
        if dns_layer.qr == 0 and dns_layer.haslayer(DNSQR):
            qname_raw = dns_layer[DNSQR].qname
            domain = (
                qname_raw.decode("utf-8", errors="replace").rstrip(".")
                if isinstance(qname_raw, bytes)
                else str(qname_raw).rstrip(".")
            )
            qtype_int = dns_layer[DNSQR].qtype
            query_type = _QTYPE_MAP.get(qtype_int, str(qtype_int))

            # Store for latency tracking
            txid = dns_layer.id
            self._pending_queries[txid] = now_mono

            self.dns_query.emit(
                {
                    "timestamp": now_iso,
                    "src_ip": src_ip,
                    "query_type": query_type,
                    "domain": domain,
                    "response": "",
                    "latency": None,
                }
            )

            # --- Anomaly: tunneling ---
            self._check_tunneling(src_ip, domain, now_iso)

            # --- Anomaly: high query rate ---
            self._check_rate(src_ip, now_mono, now_iso)

        # ------- DNS RESPONSE (qr == 1) -------
        elif dns_layer.qr == 1:
            qname_raw = dns_layer[DNSQR].qname if dns_layer.haslayer(DNSQR) else b""
            domain = (
                qname_raw.decode("utf-8", errors="replace").rstrip(".")
                if isinstance(qname_raw, bytes)
                else str(qname_raw).rstrip(".")
            )
            qtype_int = dns_layer[DNSQR].qtype if dns_layer.haslayer(DNSQR) else 0
            query_type = _QTYPE_MAP.get(qtype_int, str(qtype_int))

            # Parse response records
            responses: list[str] = []
            if dns_layer.ancount and dns_layer.ancount > 0:
                rr = dns_layer.an
                for _ in range(dns_layer.ancount):
                    if rr is None:
                        break
                    if isinstance(rr, DNSRR):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="replace").rstrip(".")
                        else:
                            rdata = str(rdata).rstrip(".")
                        responses.append(rdata)
                    rr = rr.payload if rr.payload and not isinstance(rr.payload, type(rr).payload) else None  # type: ignore[arg-type]

            # Latency estimation
            txid = dns_layer.id
            latency = None
            if txid in self._pending_queries:
                latency = round((now_mono - self._pending_queries.pop(txid)) * 1000, 2)

            self.dns_query.emit(
                {
                    "timestamp": now_iso,
                    "src_ip": src_ip,
                    "query_type": query_type,
                    "domain": domain,
                    "response": ", ".join(responses) if responses else "",
                    "latency": latency,
                }
            )

    # ------------------------------------------------------------------
    # Anomaly checks
    # ------------------------------------------------------------------
    def _check_tunneling(self, src_ip: str, domain: str, timestamp: str) -> None:
        """Flag domains with excessively long labels (tunneling indicator)."""
        labels = domain.split(".")
        for label in labels:
            if len(label) > _TUNNEL_LABEL_LEN:
                self.dns_anomaly.emit(
                    {
                        "timestamp": timestamp,
                        "src_ip": src_ip,
                        "domain": domain,
                        "anomaly_type": "DNS_TUNNELING",
                        "description": (
                            f"Domain label exceeds {_TUNNEL_LABEL_LEN} chars "
                            f"(len={len(label)}): '{label[:60]}…'"
                        ),
                    }
                )
                return  # one alert per domain is sufficient

    def _check_rate(self, src_ip: str, now_mono: float, timestamp: str) -> None:
        """Flag sources that exceed the query-rate threshold."""
        q = self._query_times[src_ip]
        q.append(now_mono)

        # Evict timestamps outside the window
        cutoff = now_mono - _RATE_WINDOW_SECONDS
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) > _RATE_THRESHOLD:
            self.dns_anomaly.emit(
                {
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "domain": "",
                    "anomaly_type": "HIGH_QUERY_RATE",
                    "description": (
                        f"{src_ip} sent {len(q)} DNS queries in the last "
                        f"{_RATE_WINDOW_SECONDS}s (threshold: {_RATE_THRESHOLD})"
                    ),
                }
            )
            # Clear the deque so we don't fire continuously every packet
            q.clear()
