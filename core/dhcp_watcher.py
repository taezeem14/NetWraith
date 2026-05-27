"""
NetWraith – DHCP Watcher Engine
================================

Monitors DHCP traffic (UDP ports 67/68) to detect rogue DHCP servers.
The watcher learns the legitimate server from the first DHCP OFFER or
ACK it observes; any subsequent offers from a different server IP
trigger a rogue-server alert.
"""

import logging
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import (  # type: ignore[import-untyped]
    BOOTP,
    DHCP,
    IP,
    UDP,
    Ether,
    sniff,
)

logger = logging.getLogger(__name__)

# DHCP message type option values
_DHCP_MSG_TYPES: dict[int, str] = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


class DHCPWatcherThread(QThread):
    """
    QThread that sniffs DHCP traffic and detects rogue servers.

    Signals
    -------
    dhcp_event : dict
        Emitted for every DHCP transaction of interest.
    rogue_alert : dict
        Emitted when a rogue DHCP server is detected.
    error_signal : str
        Emitted on unrecoverable error.
    """

    dhcp_event = pyqtSignal(dict)
    rogue_alert = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, iface: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.iface = iface
        self._stop_flag = False

        # The first DHCP server observed becomes the legitimate one
        self._legitimate_server_ip: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request the sniff loop to stop."""
        self._stop_flag = True

    def set_legitimate_server(self, ip: str) -> None:
        """Manually set the known-good DHCP server IP."""
        self._legitimate_server_ip = ip
        logger.info("Legitimate DHCP server manually set to %s", ip)

    # ------------------------------------------------------------------
    # QThread entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            kwargs: dict = {
                "filter": "udp and (port 67 or port 68)",
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _pkt: self._stop_flag,
            }
            if self.iface:
                kwargs["iface"] = self.iface

            logger.info("DHCP watcher started on iface=%s", self.iface)
            sniff(**kwargs)
            logger.info("DHCP watcher stopped.")
        except Exception as exc:
            logger.exception("DHCP watcher error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------
    def _process_packet(self, pkt) -> None:  # noqa: C901
        if self._stop_flag:
            return

        if not pkt.haslayer(DHCP):
            return

        dhcp_layer = pkt[DHCP]
        options = self._parse_options(dhcp_layer)
        msg_type_int = options.get("message-type", 0)
        msg_type = _DHCP_MSG_TYPES.get(msg_type_int, f"UNKNOWN({msg_type_int})")

        # We care about OFFER (2) and ACK (5) from servers
        if msg_type_int not in (2, 5):
            return

        # Extract relevant fields
        now_iso = datetime.now(timezone.utc).isoformat()
        bootp_layer = pkt[BOOTP] if pkt.haslayer(BOOTP) else None

        server_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        client_mac = (
            bootp_layer.chaddr[:6].hex(":") if bootp_layer else "?"
        )
        offered_ip = bootp_layer.yiaddr if bootp_layer else "?"
        lease_time = options.get("lease_time", 0)
        server_mac = pkt[Ether].src if pkt.haslayer(Ether) else "?"

        status = msg_type  # OFFER or ACK

        # Learn the legitimate server from the first OFFER/ACK
        if self._legitimate_server_ip is None:
            self._legitimate_server_ip = server_ip
            status = f"{msg_type} (learned as legitimate)"
            logger.info("Learned legitimate DHCP server: %s", server_ip)

        # Emit the event
        self.dhcp_event.emit(
            {
                "client_mac": client_mac,
                "offered_ip": offered_ip,
                "server_ip": server_ip,
                "lease_time": lease_time,
                "status": status,
                "timestamp": now_iso,
            }
        )

        # Rogue detection
        if server_ip != self._legitimate_server_ip:
            self.rogue_alert.emit(
                {
                    "server_ip": server_ip,
                    "server_mac": server_mac,
                    "timestamp": now_iso,
                    "description": (
                        f"Rogue DHCP server detected! {server_ip} "
                        f"(MAC {server_mac}) is sending {msg_type} packets. "
                        f"Legitimate server is {self._legitimate_server_ip}."
                    ),
                }
            )
            logger.warning("ROGUE DHCP SERVER: %s (%s)", server_ip, server_mac)

    # ------------------------------------------------------------------
    # DHCP option parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_options(dhcp_layer) -> dict:
        """
        Extract DHCP options into a flat dict.

        Returns keys like ``message-type``, ``lease_time``, ``server_id``, etc.
        """
        result: dict = {}
        if not hasattr(dhcp_layer, "options"):
            return result

        for opt in dhcp_layer.options:
            if isinstance(opt, tuple):
                key = opt[0]
                val = opt[1] if len(opt) > 1 else None
                result[key] = val
            elif opt == "end":
                break
        return result
