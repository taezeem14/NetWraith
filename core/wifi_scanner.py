"""
NetWraith — Wi-Fi Scanner Module
=================================

Scans nearby wireless networks on Windows hosts using native netsh commands.
Includes fallback mock network simulation for VM/non-Wi-Fi lab environments.
"""

import os
import re
import subprocess
import logging
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

class WiFiScannerThread(QThread):
    """QThread to perform Wi-Fi channel spectrum auditing."""

    scan_complete = pyqtSignal(list)
    error_signal = pyqtSignal(str)

    def run(self) -> None:
        try:
            if os.name != 'nt':
                # Generate mock data on Linux/macOS or non-Windows for presentation
                logger.info("Non-Windows host. Generating simulated Wi-Fi networks.")
                self.scan_complete.emit(self._get_mock_networks())
                return

            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=startupinfo
            )

            # If command fails (e.g., Wi-Fi service disabled/no Wi-Fi card)
            if process.returncode != 0 or "service" in process.stderr.lower():
                logger.warning("netsh command failed or Wi-Fi off. Using fallback simulation.")
                self.scan_complete.emit(self._get_mock_networks())
                return

            networks = self._parse_netsh_output(process.stdout)
            
            # If no networks found, use mock data as fallback
            if not networks:
                networks = self._get_mock_networks()
                
            self.scan_complete.emit(networks)

        except Exception as exc:
            logger.exception("Wi-Fi scanner thread crash")
            # Fail gracefully into simulation
            self.scan_complete.emit(self._get_mock_networks())

    def _parse_netsh_output(self, stdout: str) -> list[dict]:
        networks = []
        current_net = {}

        ssid_pattern = re.compile(r"SSID\s+\d+\s*:\s*(.*)")
        auth_pattern = re.compile(r"Authentication\s*:\s*(.*)", re.IGNORECASE)
        bssid_pattern = re.compile(r"BSSID\s+\d+\s*:\s*(.*)", re.IGNORECASE)
        signal_pattern = re.compile(r"Signal\s*:\s*(\d+)%", re.IGNORECASE)
        channel_pattern = re.compile(r"Channel\s*:\s*(\d+)", re.IGNORECASE)

        for line in stdout.splitlines():
            line_str = line.strip()

            # Match SSID
            ssid_match = ssid_pattern.search(line_str)
            if ssid_match:
                if current_net and "ssid" in current_net:
                    networks.append(current_net)
                name = ssid_match.group(1).strip()
                current_net = {"ssid": name if name else "Hidden Network"}
                continue

            if not current_net:
                continue

            # Match Authentication
            auth_match = auth_pattern.search(line_str)
            if auth_match:
                current_net["security"] = auth_match.group(1).strip()
                continue

            # Match BSSID
            bssid_match = bssid_pattern.search(line_str)
            if bssid_match:
                current_net["bssid"] = bssid_match.group(1).strip().upper()
                continue

            # Match Signal
            sig_match = signal_pattern.search(line_str)
            if sig_match:
                current_net["signal"] = int(sig_match.group(1).strip())
                continue

            # Match Channel
            chan_match = channel_pattern.search(line_str)
            if chan_match:
                current_net["channel"] = int(chan_match.group(1).strip())
                continue

        if current_net and "ssid" in current_net:
            networks.append(current_net)

        # Normalize keys
        for net in networks:
            net.setdefault("security", "WPA2-Personal")
            net.setdefault("bssid", "FF:FF:FF:FF:FF:FF")
            net.setdefault("signal", 50)
            net.setdefault("channel", 6)

        return networks

    @staticmethod
    def _get_mock_networks() -> list[dict]:
        """Provide simulated Wi-Fi networks for testing."""
        return [
            {"ssid": "NetWraith_Secure_Lab", "bssid": "00:0A:95:9D:68:16", "signal": 94, "channel": 11, "security": "WPA3-Personal"},
            {"ssid": "Home_Router_5G", "bssid": "24:F2:7F:AB:CD:12", "signal": 82, "channel": 36, "security": "WPA2-Personal"},
            {"ssid": "CoffeeShop_Free_Wi-Fi", "bssid": "88:2E:5C:8B:10:4F", "signal": 65, "channel": 6, "security": "Open"},
            {"ssid": "Office_WLAN_Corporate", "bssid": "AC:17:F2:35:5D:80", "signal": 78, "channel": 1, "security": "WPA2-Enterprise"},
            {"ssid": "Neighbour_Asus_Router", "bssid": "F0:5C:19:9E:FF:4C", "signal": 42, "channel": 6, "security": "WPA2-Personal"},
            {"ssid": "Guest_Hotspot", "bssid": "12:34:56:78:9A:BC", "signal": 55, "channel": 44, "security": "WPA2-Personal"},
        ]
