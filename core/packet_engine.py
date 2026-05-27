"""
NetWraith – Packet Capture Engine
==================================

General-purpose packet capture thread that stores raw packets, emits
structured summaries, and supports PCAP export. Designed to drive the
Wireshark-style packet inspector tab.
"""

import logging
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import (  # type: ignore[import-untyped]
    ARP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
    sniff,
    wrpcap,
)

logger = logging.getLogger(__name__)


class PacketCaptureThread(QThread):
    """
    QThread for live packet capture with optional BPF filtering and
    PCAP persistence.

    Signals
    -------
    packet_captured : dict
        Emitted for every captured packet with a structured summary.
    packet_count : int
        Running count of captured packets.
    error_signal : str
        Emitted on unrecoverable error.
    """

    packet_captured = pyqtSignal(dict)
    packet_count = pyqtSignal(int)
    error_signal = pyqtSignal(str)

    def __init__(
        self,
        iface: str | None = None,
        filter_str: str = "",
        output_file: str | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.iface = iface
        self.filter_str = filter_str
        self.output_file = output_file

        self._stop_flag = False
        self._packets: list = []  # raw Scapy packets
        self._counter: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Request the capture loop to stop."""
        self._stop_flag = True

    def clear(self) -> None:
        """Reset the internal packet list and counter."""
        self._packets.clear()
        self._counter = 0

    def save_pcap(self, filepath: str) -> None:
        """Export captured packets to a PCAP file."""
        if not self._packets:
            logger.warning("No packets to save.")
            return
        try:
            wrpcap(filepath, self._packets)
            logger.info("Saved %d packets → %s", len(self._packets), filepath)
        except Exception as exc:
            logger.error("Failed to save PCAP: %s", exc)

    def get_packet_detail(self, index: int) -> dict:
        """
        Return a detailed layer breakdown dict for the packet at *index*.

        Returns an empty dict if the index is out of range.
        """
        if index < 0 or index >= len(self._packets):
            return {}

        pkt = self._packets[index]
        detail: dict = {
            "number": index + 1,
            "raw_hex": self._hex_dump(bytes(pkt)),
            "layers": [],
        }

        layer = pkt
        while layer:
            layer_info: dict = {
                "name": layer.__class__.__name__,
                "fields": {},
            }
            for field in layer.fields_desc:
                fname = field.name
                try:
                    val = getattr(layer, fname, None)
                    # Convert bytes to hex string for readability
                    if isinstance(val, bytes):
                        val = val.hex()
                    layer_info["fields"][fname] = str(val)
                except Exception:
                    layer_info["fields"][fname] = "?"
            detail["layers"].append(layer_info)
            layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) else None

        return detail

    # ------------------------------------------------------------------
    # QThread entry
    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            kwargs: dict = {
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _pkt: self._stop_flag,
            }
            if self.iface:
                kwargs["iface"] = self.iface
            if self.filter_str:
                kwargs["filter"] = self.filter_str

            logger.info(
                "Packet capture started iface=%s filter='%s'",
                self.iface,
                self.filter_str,
            )
            sniff(**kwargs)

            # Auto-save if an output file was specified
            if self.output_file and self._packets:
                self.save_pcap(self.output_file)

            logger.info("Packet capture stopped. %d packets captured.", self._counter)
        except Exception as exc:
            logger.exception("Packet capture error")
            self.error_signal.emit(str(exc))

    # ------------------------------------------------------------------
    # Packet handler
    # ------------------------------------------------------------------
    def _process_packet(self, pkt) -> None:
        if self._stop_flag:
            return

        self._packets.append(pkt)
        self._counter += 1

        src_ip = ""
        dst_ip = ""
        protocol = "OTHER"
        info = ""

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

        # Determine protocol and build info summary
        if pkt.haslayer(DNS):
            protocol = "DNS"
            dns_layer = pkt[DNS]
            if dns_layer.qr == 0 and dns_layer.qdcount:
                qname = dns_layer.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace").rstrip(".")
                info = f"Query: {qname}"
            elif dns_layer.qr == 1:
                info = f"Response (ancount={dns_layer.ancount})"
        elif pkt.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = pkt[TCP]
            flags = str(tcp_layer.flags)
            info = f"{tcp_layer.sport} → {tcp_layer.dport} [{flags}]"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp_layer = pkt[UDP]
            info = f"{udp_layer.sport} → {udp_layer.dport} len={udp_layer.len}"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp_layer = pkt[ICMP]
            info = f"type={icmp_layer.type} code={icmp_layer.code}"
        elif pkt.haslayer(ARP):
            protocol = "ARP"
            arp_layer = pkt[ARP]
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            op_str = "request" if arp_layer.op == 1 else "reply"
            info = f"{op_str} {arp_layer.psrc} → {arp_layer.pdst}"

        # Collect layer names
        layers: list[str] = []
        layer = pkt
        while layer:
            layers.append(layer.__class__.__name__)
            layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) else None

        pkt_len = len(pkt)
        raw_hex = self._hex_dump(bytes(pkt), max_bytes=64)

        summary: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": pkt_len,
            "info": info,
            "layers": layers,
            "raw_hex": raw_hex,
            "number": self._counter,
        }

        self.packet_captured.emit(summary)
        self.packet_count.emit(self._counter)

    # ------------------------------------------------------------------
    # Hex dump helper
    # ------------------------------------------------------------------
    @staticmethod
    def _hex_dump(data: bytes, max_bytes: int = 0) -> str:
        """
        Generate a classic hex-dump string from *data*.

        Parameters
        ----------
        data : bytes
            Raw packet bytes.
        max_bytes : int
            If > 0, truncate after this many bytes.

        Returns
        -------
        str
            Multi-line hex dump.
        """
        if max_bytes > 0:
            data = data[:max_bytes]

        lines: list[str] = []
        for offset in range(0, len(data), 16):
            chunk = data[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08x}  {hex_part:<48s}  {ascii_part}")
        return "\n".join(lines)
