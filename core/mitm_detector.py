"""
NetWraith – Man-in-the-Middle Detector Engine
===============================================

Runs continuous checks (every 5 seconds) looking for indicators of
active MITM attacks:

1. **GATEWAY_MAC_CHANGE** – the gateway's ARP-resolved MAC differs from
   the expected value.  *(CRITICAL)*
2. **DUPLICATE_IP** – another host claims our own IP address.  *(CRITICAL)*
3. **ICMP_REDIRECT** – an ICMP redirect (type 5) is observed on the wire.
   *(WARNING)*
4. **TTL_ANOMALY** – the TTL value from the gateway changes suddenly,
   suggesting an intercepting hop.  *(WARNING)*
5. **MAC_CONFLICT** – multiple IPs resolve to the same MAC address.
   *(WARNING)*

Alerts are deduplicated over a 30-second sliding window so the UI
receives at most one alert per type+source every half-minute.
"""

import logging
import time
import threading
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import (  # type: ignore[import-untyped]
    ARP,
    Ether,
    ICMP,
    IP,
    conf,
    sniff,
    sr1,
    srp,
)

logger = logging.getLogger(__name__)

_DEDUP_WINDOW_SECONDS = 30
_CHECK_INTERVAL_SECONDS = 5


class MITMDetectorThread(QThread):
    """
    QThread that runs periodic MITM detection checks.

    Signals
    -------
    mitm_alert : dict
        Emitted when a potential MITM attack is detected.
    status_update : dict
        Emitted after each successful check with the result.
    error_signal : str
        Emitted on unrecoverable error.
    """

    mitm_alert = pyqtSignal(dict)
    status_update = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        iface: str | None = None,
        gateway_ip: str = "",
        gateway_mac: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac.upper()

        self._stop_flag = False
        # Track alert dedup: (alert_type, source_key) → mono timestamp
        self._alert_history: dict[tuple[str, str], float] = {}
        # ARP table built during monitoring
        self._arp_table: dict[str, str] = {}
        # TTL baseline for the gateway
        self._gateway_ttl: int | None = None

        # Thread for ICMP redirect sniffing (runs concurrently)
        self._sniffer_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request the detector to stop."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # QThread entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            # Start ICMP redirect sniffer in a background thread
            self._sniffer_thread = threading.Thread(
                target=self._icmp_sniffer, daemon=True
            )
            self._sniffer_thread.start()

            logger.info(
                "MITM detector started  gw_ip=%s gw_mac=%s iface=%s",
                self.gateway_ip,
                self.gateway_mac,
                self.iface,
            )

            while not self._stop_flag:
                self._check_gateway_mac()
                if self._stop_flag:
                    break

                self._check_duplicate_ip()
                if self._stop_flag:
                    break

                self._check_ttl_anomaly()
                if self._stop_flag:
                    break

                self._check_mac_conflicts()
                if self._stop_flag:
                    break

                # Sleep in small increments so we can exit promptly
                for _ in range(int(_CHECK_INTERVAL_SECONDS * 10)):
                    if self._stop_flag:
                        break
                    time.sleep(0.1)

            logger.info("MITM detector stopped.")
        except Exception as exc:
            logger.exception("MITM detector error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # 1. Gateway MAC monitoring
    # ------------------------------------------------------------------
    def _check_gateway_mac(self) -> None:
        """ARP-resolve the gateway and compare its MAC to the expected one."""
        if not self.gateway_ip or not self.gateway_mac:
            return

        resolved_mac = self._arp_resolve(self.gateway_ip)
        if not resolved_mac:
            self._emit_status("gateway_mac_check", "no_response")
            return

        resolved_mac = resolved_mac.upper()
        self._arp_table[self.gateway_ip] = resolved_mac

        if resolved_mac != self.gateway_mac:
            self._emit_alert(
                alert_type="GATEWAY_MAC_CHANGE",
                source_key=self.gateway_ip,
                severity="CRITICAL",
                description=(
                    f"Gateway {self.gateway_ip} MAC changed! "
                    f"Expected {self.gateway_mac}, got {resolved_mac}."
                ),
                details={
                    "gateway_ip": self.gateway_ip,
                    "expected_mac": self.gateway_mac,
                    "detected_mac": resolved_mac,
                },
            )
        else:
            self._emit_status("gateway_mac_check", "OK")

    # ------------------------------------------------------------------
    # 2. Duplicate IP detection
    # ------------------------------------------------------------------
    def _check_duplicate_ip(self) -> None:
        """Send an ARP for our own IP; if someone else answers → dup."""
        try:
            my_ip = conf.route.route("0.0.0.0")[1]  # our IP via default route
        except Exception:
            return

        if not my_ip or my_ip == "0.0.0.0":
            return

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=my_ip)
        kwargs: dict = {"timeout": 2, "verbose": False}
        if self.iface:
            kwargs["iface"] = self.iface
        answered, _ = srp(pkt, **kwargs)

        for _, rcv in answered:
            responder_mac = rcv.hwsrc.upper()
            try:
                my_mac = Ether().src.upper()
            except Exception:
                my_mac = ""

            if responder_mac and responder_mac != my_mac:
                self._emit_alert(
                    alert_type="DUPLICATE_IP",
                    source_key=my_ip,
                    severity="CRITICAL",
                    description=(
                        f"Another host ({responder_mac}) is claiming our "
                        f"IP address {my_ip}!"
                    ),
                    details={
                        "our_ip": my_ip,
                        "our_mac": my_mac,
                        "conflicting_mac": responder_mac,
                    },
                )
                return

        self._emit_status("duplicate_ip_check", "OK")

    # ------------------------------------------------------------------
    # 3. ICMP redirect sniffing (runs in its own thread)
    # ------------------------------------------------------------------
    def _icmp_sniffer(self) -> None:
        """Sniff for ICMP redirect packets (type 5)."""
        try:
            kwargs: dict = {
                "filter": "icmp",
                "prn": self._process_icmp,
                "store": False,
                "stop_filter": lambda _pkt: self._stop_flag,
            }
            if self.iface:
                kwargs["iface"] = self.iface
            sniff(**kwargs)
        except Exception as exc:
            logger.warning("ICMP sniffer error: %s", exc)

    def _process_icmp(self, pkt) -> None:
        if self._stop_flag:
            return
        if not pkt.haslayer(ICMP):
            return

        icmp_layer = pkt[ICMP]
        # Type 5 = Redirect
        if icmp_layer.type == 5:
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
            self._emit_alert(
                alert_type="ICMP_REDIRECT",
                source_key=src_ip,
                severity="WARNING",
                description=(
                    f"ICMP Redirect received from {src_ip} – may indicate "
                    f"route manipulation."
                ),
                details={
                    "src_ip": src_ip,
                    "icmp_type": icmp_layer.type,
                    "icmp_code": icmp_layer.code,
                },
            )

    # ------------------------------------------------------------------
    # 4. TTL anomaly detection
    # ------------------------------------------------------------------
    def _check_ttl_anomaly(self) -> None:
        """Ping the gateway and check for sudden TTL shifts."""
        if not self.gateway_ip:
            return

        try:
            pkt = IP(dst=self.gateway_ip) / ICMP()
            resp = sr1(pkt, timeout=2, verbose=False)
            if resp is None or not resp.haslayer(IP):
                self._emit_status("ttl_check", "no_response")
                return

            ttl = resp[IP].ttl

            if self._gateway_ttl is None:
                # Establish baseline
                self._gateway_ttl = ttl
                self._emit_status("ttl_check", f"baseline_ttl={ttl}")
                return

            # Allow small jitter (±5), flag larger changes
            diff = abs(ttl - self._gateway_ttl)
            if diff > 5:
                self._emit_alert(
                    alert_type="TTL_ANOMALY",
                    source_key=self.gateway_ip,
                    severity="WARNING",
                    description=(
                        f"Gateway TTL changed from {self._gateway_ttl} to "
                        f"{ttl} (Δ{diff}) – possible interception."
                    ),
                    details={
                        "gateway_ip": self.gateway_ip,
                        "baseline_ttl": self._gateway_ttl,
                        "current_ttl": ttl,
                        "delta": diff,
                    },
                )
                # Update baseline to avoid continuous re-alerting
                self._gateway_ttl = ttl
            else:
                self._emit_status("ttl_check", f"ttl={ttl} (OK)")
        except Exception as exc:
            logger.debug("TTL check error: %s", exc)

    # ------------------------------------------------------------------
    # 5. ARP table consistency – MAC conflicts
    # ------------------------------------------------------------------
    def _check_mac_conflicts(self) -> None:
        """Detect multiple IPs resolving to the same MAC."""
        mac_to_ips: dict[str, list[str]] = {}
        for ip, mac in self._arp_table.items():
            mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                self._emit_alert(
                    alert_type="MAC_CONFLICT",
                    source_key=mac,
                    severity="WARNING",
                    description=(
                        f"MAC {mac} is associated with multiple IPs: "
                        f"{', '.join(ips)}"
                    ),
                    details={"mac": mac, "ips": ips},
                )

        self._emit_status("mac_conflict_check", f"table_size={len(self._arp_table)}")

    # ------------------------------------------------------------------
    # ARP resolution helper
    # ------------------------------------------------------------------
    def _arp_resolve(self, ip: str) -> str | None:
        """Resolve an IP to a MAC via ARP. Returns None on failure."""
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            kwargs: dict = {"timeout": 2, "verbose": False}
            if self.iface:
                kwargs["iface"] = self.iface
            answered, _ = srp(pkt, **kwargs)
            for _, rcv in answered:
                return rcv.hwsrc
        except Exception as exc:
            logger.debug("ARP resolve failed for %s: %s", ip, exc)
        return None

    # ------------------------------------------------------------------
    # Signal emission helpers
    # ------------------------------------------------------------------
    def _emit_alert(
        self,
        *,
        alert_type: str,
        source_key: str,
        severity: str,
        description: str,
        details: dict,
    ) -> None:
        """Emit a mitm_alert signal with 30-second deduplication."""
        key = (alert_type, source_key)
        now = time.monotonic()
        last = self._alert_history.get(key, 0.0)

        if now - last < _DEDUP_WINDOW_SECONDS:
            return  # suppress duplicate

        self._alert_history[key] = now
        self.mitm_alert.emit(
            {
                "alert_type": alert_type,
                "description": description,
                "details": details,
                "severity": severity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.warning("[MITM %s] %s", alert_type, description)

    def _emit_status(self, check_type: str, result: str) -> None:
        """Emit a status_update signal."""
        self.status_update.emit(
            {
                "gateway_ip": self.gateway_ip,
                "gateway_mac": self.gateway_mac,
                "check_type": check_type,
                "result": result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
