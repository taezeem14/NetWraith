"""
NetWraith — Threat Intelligence & GeoIP Lookup Engine
======================================================

Background thread that resolves public IP addresses using ip-api.com.
Maintains a thread-safe request queue, checks cache, filters local/private IPs,
and rates lookups to avoid exceeding API limits.
"""

import logging
import queue
import time
import requests
import ipaddress
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

# Free ip-api.com limit is 45 requests per minute (approx 1 request per 1.34s)
LOOKUP_DELAY = 1.5

class ThreatIntelThread(QThread):
    """
    QThread for resolving public IP details and threat scores in the background.

    Signals
    -------
    intel_result : dict
        Emitted when an IP resolution completes.
    error_signal : str
        Emitted on request or parsing failure.
    """

    intel_result = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._stop_flag = False
        self._queue: queue.Queue[str] = queue.Queue()
        self._cache: dict[str, dict] = {}
        
        # Simple local suspicious IP baseline for simulated threat checking
        self._suspicious_subnets = [
            "185.", "45.", "193.", "91.", "103.", "141.", "223."
        ]

    def add_ip(self, ip: str) -> None:
        """Add an IP address to the lookup queue."""
        if not ip:
            return
        
        # Quick validation
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
                return  # Skip private/local ranges
        except ValueError:
            return  # Invalid IP address

        # If it's already in queue or cache, don't duplicate
        if ip in self._cache:
            # Re-emit cached result immediately to keep UI responsive
            self.intel_result.emit(self._cache[ip])
            return

        self._queue.put(ip)

    def stop(self) -> None:
        """Request the thread to terminate."""
        self._stop_flag = True
        # Put sentinel to wake up the queue get blocking call
        self._queue.put("")

    def run(self) -> None:
        logger.info("Threat intelligence lookup thread started.")
        while not self._stop_flag:
            try:
                # Wait for next IP
                ip = self._queue.get()
                if not ip or self._stop_flag:
                    break

                if ip in self._cache:
                    self._queue.task_done()
                    continue

                # Rate limiter sleep before lookup
                time.sleep(LOOKUP_DELAY)
                if self._stop_flag:
                    break

                result = self._lookup_ip(ip)
                if result:
                    self._cache[ip] = result
                    self.intel_result.emit(result)

                self._queue.task_done()

            except Exception as exc:
                logger.exception("Error in ThreatIntelThread loop")
                self.error_signal.emit(str(exc))

        logger.info("Threat intelligence lookup thread stopped.")

    def _lookup_ip(self, ip: str) -> dict | None:
        """Fetch GeoIP info and assess threat score."""
        url = f"http://ip-api.com/json/{ip}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    country = data.get("country", "Unknown")
                    region = data.get("regionName", "Unknown")
                    isp = data.get("isp", "Unknown")
                    org = data.get("org", "Unknown")
                    
                    # Heuristic Threat Score (0 - 100) based on ISP & Subnet reputation
                    threat_score = 0
                    threat_flags = []
                    
                    # Flag known generic hosting/VPN service providers
                    isp_lower = isp.lower()
                    if any(x in isp_lower for x in ["hosting", "vpn", "digitalocean", "linode", "m247", "leaseweb", "ovh", "server"]):
                        threat_score += 45
                        threat_flags.append("Hosting/VPN Provider")
                    
                    # Flag suspicious subnet prefixes
                    if any(ip.startswith(prefix) for prefix in self._suspicious_subnets):
                        threat_score += 30
                        threat_flags.append("High-Risk Subnet")
                    
                    if not threat_flags:
                        threat_flags.append("Clean")

                    return {
                        "ip": ip,
                        "country": country,
                        "region": region,
                        "isp": isp,
                        "org": org,
                        "threat_score": min(threat_score, 100),
                        "threat_flags": ", ".join(threat_flags),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                else:
                    logger.warning("ip-api query failed for IP %s: %s", ip, data.get("message"))
            elif response.status_code == 429:
                logger.warning("ip-api rate limit hit. Slowing down lookups.")
                time.sleep(5)  # Backoff
        except Exception as exc:
            logger.debug("Failed to lookup GeoIP for %s: %s", ip, exc)
            # Fallback to local offline estimation on failure to keep UI moving
            return self._get_offline_estimate(ip)

        return None

    def _get_offline_estimate(self, ip: str) -> dict:
        """Provide fallback offline response when API is unreachable."""
        threat_score = 15 if any(ip.startswith(prefix) for prefix in self._suspicious_subnets) else 0
        flags = "Offline Check (High-Risk)" if threat_score > 0 else "Offline Check"
        return {
            "ip": ip,
            "country": "Offline / Cache",
            "region": "Offline / Cache",
            "isp": "Unknown ISP",
            "org": "Unknown Organization",
            "threat_score": threat_score,
            "threat_flags": flags,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
