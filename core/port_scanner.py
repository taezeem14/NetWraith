"""
NetWraith – Port Scanner Engine
================================

Multi-threaded port scanner supporting three scan modes:

* **tcp_connect** – full TCP handshake via ``socket.connect_ex()``.
* **syn** – half-open SYN scan via Scapy ``sr1()`` (requires elevated
  privileges).
* **udp** – UDP probe that checks for ICMP Port Unreachable responses.

Open ports get a best-effort service name and optional banner grab.
"""

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import ICMP, IP, TCP, UDP, sr1  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# Fallback service name map for common ports
PORT_SERVICES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1434: "mssql-udp",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


class PortScannerThread(QThread):
    """
    QThread that scans a range of ports on a target host.

    Signals
    -------
    port_result : dict
        Emitted per port with scan result.
    scan_progress : (int, int)
        ``(current_port_index, total_ports)`` progress updates.
    scan_complete : list[dict]
        Full results list emitted after all ports are scanned.
    error_signal : str
        Emitted on unrecoverable error.
    """

    port_result = pyqtSignal(dict)
    scan_progress = pyqtSignal(int, int)
    scan_complete = pyqtSignal(list)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        target_ip: str,
        port_range: tuple[int, int] = (1, 1024),
        scan_type: str = "tcp_connect",
        thread_count: int = 50,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.target_ip = target_ip
        self.port_range = port_range
        self.scan_type = scan_type
        self.thread_count = thread_count

        self._stop_flag = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request scan to stop."""
        self._stop_flag = True

    # ------------------------------------------------------------------
    # QThread entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            start_port, end_port = self.port_range
            ports = list(range(start_port, end_port + 1))
            total = len(ports)
            results: list[dict] = []
            progress_counter = 0

            logger.info(
                "Port scan started target=%s ports=%d-%d type=%s threads=%d",
                self.target_ip,
                start_port,
                end_port,
                self.scan_type,
                self.thread_count,
            )

            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, port): port for port in ports
                }

                for future in as_completed(future_to_port):
                    if self._stop_flag:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    progress_counter += 1
                    port = future_to_port[future]

                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "port": port,
                            "protocol": self._protocol_label(),
                            "state": "error",
                            "service": "",
                            "banner": "",
                        }
                        logger.debug("Port %d scan error: %s", port, exc)

                    results.append(result)
                    self.port_result.emit(result)
                    self.scan_progress.emit(progress_counter, total)

            # Sort by port number before emitting
            results.sort(key=lambda r: r.get("port", 0))
            self.scan_complete.emit(results)
            logger.info("Port scan complete. %d ports scanned.", total)

        except Exception as exc:
            logger.exception("Port scanner error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # Scan dispatcher
    # ------------------------------------------------------------------
    def _scan_port(self, port: int) -> dict:
        """Route to the correct scan method."""
        if self._stop_flag:
            return self._empty_result(port, "skipped")

        if self.scan_type == "syn":
            return self._syn_scan(port)
        if self.scan_type == "udp":
            return self._udp_scan(port)
        return self._tcp_connect_scan(port)

    # ------------------------------------------------------------------
    # TCP Connect scan
    # ------------------------------------------------------------------
    def _tcp_connect_scan(self, port: int) -> dict:
        """Full TCP handshake scan."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            errno = sock.connect_ex((self.target_ip, port))
            sock.close()

            if errno == 0:
                service = self._service_name(port, "tcp")
                banner = self._grab_banner(port)
                return self._make_result(port, "open", service, banner, "TCP")
            return self._make_result(port, "closed", "", "", "TCP")
        except socket.timeout:
            return self._make_result(port, "filtered", "", "", "TCP")
        except Exception:
            return self._make_result(port, "error", "", "", "TCP")

    # ------------------------------------------------------------------
    # SYN (half-open) scan
    # ------------------------------------------------------------------
    def _syn_scan(self, port: int) -> dict:
        """Scapy SYN scan – requires elevated privileges."""
        try:
            pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=2, verbose=False)

            if resp is None:
                return self._make_result(port, "filtered", "", "", "TCP")

            if resp.haslayer(TCP):
                tcp_flags = resp[TCP].flags
                # SYN-ACK → open
                if tcp_flags == 0x12:  # SA
                    service = self._service_name(port, "tcp")
                    return self._make_result(port, "open", service, "", "TCP")
                # RST → closed
                if tcp_flags & 0x04:  # R
                    return self._make_result(port, "closed", "", "", "TCP")

            return self._make_result(port, "filtered", "", "", "TCP")
        except Exception:
            return self._make_result(port, "error", "", "", "TCP")

    # ------------------------------------------------------------------
    # UDP scan
    # ------------------------------------------------------------------
    def _udp_scan(self, port: int) -> dict:
        """UDP scan – send empty datagram, look for ICMP unreachable."""
        try:
            pkt = IP(dst=self.target_ip) / UDP(dport=port)
            resp = sr1(pkt, timeout=3, verbose=False)

            if resp is None:
                # No response → open|filtered
                service = self._service_name(port, "udp")
                return self._make_result(port, "open|filtered", service, "", "UDP")

            if resp.haslayer(ICMP):
                icmp_type = resp[ICMP].type
                icmp_code = resp[ICMP].code
                # Destination unreachable, port unreachable
                if icmp_type == 3 and icmp_code == 3:
                    return self._make_result(port, "closed", "", "", "UDP")
                # Other unreachable codes → filtered
                if icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
                    return self._make_result(port, "filtered", "", "", "UDP")

            if resp.haslayer(UDP):
                service = self._service_name(port, "udp")
                return self._make_result(port, "open", service, "", "UDP")

            return self._make_result(port, "open|filtered", "", "", "UDP")
        except Exception:
            return self._make_result(port, "error", "", "", "UDP")

    # ------------------------------------------------------------------
    # Banner grabbing
    # ------------------------------------------------------------------
    def _grab_banner(self, port: int) -> str:
        """Attempt to receive the first 256 bytes from an open TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_ip, port))
            # Some services require a nudge
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
            banner = sock.recv(256)
            sock.close()
            return banner.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _service_name(self, port: int, proto: str = "tcp") -> str:
        """Look up the service name for a port."""
        try:
            return socket.getservbyport(port, proto)
        except OSError:
            return PORT_SERVICES.get(port, "")

    def _protocol_label(self) -> str:
        if self.scan_type == "udp":
            return "UDP"
        return "TCP"

    @staticmethod
    def _make_result(
        port: int, state: str, service: str, banner: str, protocol: str
    ) -> dict:
        return {
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "banner": banner,
        }

    def _empty_result(self, port: int, state: str) -> dict:
        return self._make_result(port, state, "", "", self._protocol_label())
