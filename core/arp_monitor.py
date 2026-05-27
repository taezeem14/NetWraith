"""
NetWraith – ARP Monitor Engine
===============================

Continuously sniffs ARP reply packets on the selected interface and
maintains a live ARP table. Emits alerts when:

* **ARP_SPOOF** – a known IP suddenly maps to a different MAC address.
* **GRATUITOUS_ARP** – the sender and target protocol address are identical
  (often benign, but can indicate poisoning).

Alerts are deduplicated with a 30-second sliding window so the UI is not
flooded with duplicate notifications.
"""

import logging
import time
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import ARP, sniff  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

_DEDUP_WINDOW_SECONDS = 30


class ARPMonitorThread(QThread):
    """
    QThread that sniffs ARP replies and detects anomalies.

    Signals
    -------
    arp_packet : dict
        Emitted for every observed ARP reply.
    arp_alert : dict
        Emitted when suspicious ARP activity is detected.
    error_signal : str
        Emitted on unrecoverable error.
    """

    arp_packet = pyqtSignal(dict)
    arp_alert = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, iface: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.iface = iface
        self._stop_flag = False

        # Live ARP table: ip → mac
        self._arp_table: dict[str, str] = {}
        # Baseline provided by the caller
        self._baseline: dict[str, str] = {}
        # Dedup: (alert_type, ip) → last_alert_timestamp
        self._alert_history: dict[tuple[str, str], float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def set_baseline(self, hosts: dict[str, str]) -> None:
        """
        Load known IP → MAC mappings as baseline.

        Parameters
        ----------
        hosts : dict
            ``{ip: mac, …}`` mapping of trusted addresses.
        """
        self._baseline = {ip: mac.upper() for ip, mac in hosts.items()}
        # Seed the live table with the baseline
        self._arp_table.update(self._baseline)

    def stop(self) -> None:
        """Request the sniff loop to stop."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # QThread entry point
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            kwargs: dict = {
                "filter": "arp",
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _pkt: self._stop_flag,
            }
            if self.iface:
                kwargs["iface"] = self.iface

            logger.info("ARP monitor started on iface=%s", self.iface)
            sniff(**kwargs)
            logger.info("ARP monitor stopped.")
        except Exception as exc:
            logger.exception("ARP monitor error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------
    def _process_packet(self, pkt) -> None:
        """Handle a single ARP packet."""
        if self._stop_flag:
            return

        if not pkt.haslayer(ARP):
            return

        arp_layer = pkt[ARP]

        # We only care about ARP replies (is-at, op == 2)
        if arp_layer.op != 2:
            return

        src_ip: str = arp_layer.psrc
        src_mac: str = arp_layer.hwsrc.upper()
        dst_ip: str = arp_layer.pdst

        now_iso = datetime.now(timezone.utc).isoformat()
        expected_mac = self._arp_table.get(src_ip, "")

        # Emit every ARP reply as an observation
        self.arp_packet.emit(
            {
                "ip": src_ip,
                "mac": src_mac,
                "expected_mac": expected_mac,
                "status": "OK" if (not expected_mac or expected_mac == src_mac) else "CHANGED",
                "timestamp": now_iso,
            }
        )

        # --- Anomaly checks ---

        # 1. Gratuitous ARP (sender IP == target IP)
        if src_ip == dst_ip:
            self._fire_alert(
                src_ip,
                alert_type="GRATUITOUS_ARP",
                expected_mac=expected_mac,
                detected_mac=src_mac,
            )

        # 2. MAC change for a known IP → potential spoof
        if expected_mac and expected_mac != src_mac:
            self._fire_alert(
                src_ip,
                alert_type="ARP_SPOOF",
                expected_mac=expected_mac,
                detected_mac=src_mac,
            )

        # Update the live ARP table
        self._arp_table[src_ip] = src_mac

    # ------------------------------------------------------------------
    # Alert helpers
    # ------------------------------------------------------------------
    def _fire_alert(
        self,
        ip: str,
        *,
        alert_type: str,
        expected_mac: str,
        detected_mac: str,
    ) -> None:
        """Emit an alert if the dedup window has elapsed."""
        key = (alert_type, ip)
        now = time.monotonic()

        last = self._alert_history.get(key, 0.0)
        if now - last < _DEDUP_WINDOW_SECONDS:
            return  # duplicate suppressed

        self._alert_history[key] = now
        self.arp_alert.emit(
            {
                "ip": ip,
                "expected_mac": expected_mac,
                "detected_mac": detected_mac,
                "alert_type": alert_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.warning(
            "ARP alert [%s] ip=%s expected=%s detected=%s",
            alert_type,
            ip,
            expected_mac,
            detected_mac,
        )
