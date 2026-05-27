"""
NetWraith – Network Scanner (ARP Ping Sweep)
=============================================

Discovers live hosts on a local subnet via ARP requests, resolves their
MAC vendor and hostname, then classifies each host against a trusted
baseline stored in ``trusted_hosts.json``.

Status codes
------------
* **NEW** – host not present in the baseline
* **TRUSTED** – host present and MAC matches
* **CHANGED** – IP exists in baseline but MAC has changed
* **SUSPICIOUS** – MAC address seen on a different IP in the baseline
"""

import json
import logging
import os
import socket
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import ARP, Ether, srp  # type: ignore[import-untyped]

from .vendor_lookup import VendorLookup

logger = logging.getLogger(__name__)


class ScannerThread(QThread):
    """
    QThread that performs an ARP ping sweep on the given IP range.

    Signals
    -------
    host_found : dict
        Emitted for every discovered host.
    scan_complete : list[dict]
        Emitted once the scan finishes, carrying the full result list.
    error_signal : str
        Emitted when an unrecoverable error occurs.
    """

    host_found = pyqtSignal(dict)
    scan_complete = pyqtSignal(list)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        ip_range: str,
        trusted_hosts_path: str,
        iface: str | None = None,
        timeout: int = 3,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.ip_range = ip_range
        self.trusted_hosts_path = trusted_hosts_path
        self.iface = iface
        self.timeout = timeout

        self._stop_flag = False
        self._vendor_lookup = VendorLookup()
        self._trusted_hosts: dict = {}  # ip -> {mac, hostname, …}

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request a graceful stop."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # QThread entry point
    # ------------------------------------------------------------------
    def run(self) -> None:  # noqa: C901 – complexity is intentional
        try:
            self._load_trusted_hosts()
            is_first_scan = len(self._trusted_hosts) == 0

            # Build ARP request frame
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range)

            # Send and receive
            kwargs: dict = {"timeout": self.timeout, "verbose": False}
            if self.iface:
                kwargs["iface"] = self.iface
            answered, _ = srp(arp_request, **kwargs)

            results: list[dict] = []
            now = datetime.now(timezone.utc).isoformat()

            # Build a reverse map: MAC -> list of IPs in the baseline
            baseline_mac_to_ips: dict[str, list[str]] = {}
            for ip, info in self._trusted_hosts.items():
                mac = info.get("mac", "").upper()
                baseline_mac_to_ips.setdefault(mac, []).append(ip)

            for _, received in answered:
                if self._stop_flag:
                    break

                ip = received.psrc
                mac = received.hwsrc.upper()
                vendor = self._vendor_lookup.lookup(mac)
                hostname = self._resolve_hostname(ip)

                # Classify the host
                status = self._classify(ip, mac, baseline_mac_to_ips)

                host_info: dict = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "status": status,
                    "first_seen": now,
                    "last_seen": now,
                }
                results.append(host_info)
                self.host_found.emit(host_info)

            # Persist baseline on the very first scan
            if is_first_scan and results:
                self._save_trusted_hosts(results)

            self.scan_complete.emit(results)

        except Exception as exc:
            logger.exception("Scanner error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # Classification logic
    # ------------------------------------------------------------------
    def _classify(
        self,
        ip: str,
        mac: str,
        baseline_mac_to_ips: dict[str, list[str]],
    ) -> str:
        """Return the status string for a discovered host."""
        if ip in self._trusted_hosts:
            expected_mac = self._trusted_hosts[ip].get("mac", "").upper()
            if expected_mac == mac:
                return "TRUSTED"
            return "CHANGED"

        # IP not in baseline – check if the MAC appears under a different IP
        if mac in baseline_mac_to_ips:
            known_ips = baseline_mac_to_ips[mac]
            if ip not in known_ips:
                return "SUSPICIOUS"

        return "NEW"

    # ------------------------------------------------------------------
    # Trusted-hosts persistence
    # ------------------------------------------------------------------
    def _load_trusted_hosts(self) -> None:
        """Load the trusted hosts baseline from disk."""
        if not self.trusted_hosts_path or not os.path.isfile(self.trusted_hosts_path):
            self._trusted_hosts = {}
            return
        try:
            with open(self.trusted_hosts_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._trusted_hosts = data
            elif isinstance(data, list):
                # Convert list-of-dicts to ip-keyed dict
                self._trusted_hosts = {h["ip"]: h for h in data if "ip" in h}
            else:
                self._trusted_hosts = {}
        except Exception as exc:
            logger.warning("Could not load trusted hosts: %s", exc)
            self._trusted_hosts = {}

    def _save_trusted_hosts(self, results: list[dict]) -> None:
        """Save discovered hosts as the new baseline."""
        try:
            baseline: dict = {r["ip"]: r for r in results}
            os.makedirs(os.path.dirname(self.trusted_hosts_path) or ".", exist_ok=True)
            with open(self.trusted_hosts_path, "w", encoding="utf-8") as fh:
                json.dump(baseline, fh, indent=2)
            logger.info("Baseline saved → %s", self.trusted_hosts_path)
        except Exception as exc:
            logger.warning("Could not save trusted hosts: %s", exc)

    # ------------------------------------------------------------------
    # Hostname resolution
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_hostname(ip: str) -> str:
        """Best-effort FQDN resolution for *ip*."""
        try:
            hostname = socket.getfqdn(ip)
            # getfqdn returns the IP itself when it cannot resolve
            if hostname == ip:
                return ""
            return hostname
        except Exception:
            return ""
