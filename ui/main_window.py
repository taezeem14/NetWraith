"""
NetWraith – Main Application Window
====================================

Central hub that wires together every tab widget and every core engine thread.
Handles interface detection, thread lifecycle, system tray, keyboard shortcuts,
and signal routing between the UI tabs and the Scapy-based backend engines.
"""

import ipaddress
import json
import logging
import os
import socket
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, QSize, QTimer, pyqtSlot
from PyQt6.QtGui import (
    QAction,
    QFont,
    QIcon,
    QKeySequence,
    QShortcut,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QSpinBox,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QMenu,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Theme constants
# ---------------------------------------------------------------------------
BG_DARK = "#0d0f14"
BG_PANEL = "#1a1d24"
ACCENT_CYAN = "#00e5ff"
DANGER_RED = "#ff4c4c"
BORDER_COLOR = "#2a2d35"
TEXT_PRIMARY = "#ffffff"
TEXT_SECONDARY = "#8a8f98"
WARNING_AMBER = "#ffb74d"
SUCCESS_GREEN = "#4caf50"
PURPLE = "#bb86fc"

# ---------------------------------------------------------------------------
# Tab widgets
# ---------------------------------------------------------------------------
from ui.dashboard_tab import DashboardTab
from ui.hosts_tab import HostsTab
from ui.arp_tab import ARPTab
from ui.dns_tab import DNSTab
from ui.packets_tab import PacketsTab
from ui.ports_tab import PortsTab
from ui.dhcp_tab import DHCPTab
from ui.ssl_tab import SSLTab
from ui.mitm_tab import MITMTab
from ui.logs_tab import LogsTab

# ---------------------------------------------------------------------------
# Core engine threads
# ---------------------------------------------------------------------------
from core.scanner import ScannerThread
from core.arp_monitor import ARPMonitorThread
from core.dns_sniffer import DNSSnifferThread
from core.packet_engine import PacketCaptureThread
from core.port_scanner import PortScannerThread
from core.dhcp_watcher import DHCPWatcherThread
from core.ssl_inspector import SSLInspectorThread
from core.mitm_detector import MITMDetectorThread

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Network helper — netifaces import with fallback
# ---------------------------------------------------------------------------
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    logger.warning("netifaces not installed – interface auto-detection disabled")


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                         Settings Dialog                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class SettingsDialog(QDialog):
    """Simple dark-themed settings dialog."""

    def __init__(self, settings: dict, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetWraith Settings")
        self.setFixedSize(420, 340)
        self.settings = dict(settings)  # work on a copy
        self._build_ui()

    # ------------------------------------------------------------------ ui
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        title = QLabel("⚙️  Settings")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {ACCENT_CYAN}; background: transparent;")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(12)

        # Scan timeout
        self.scan_timeout_spin = QSpinBox()
        self.scan_timeout_spin.setRange(1, 120)
        self.scan_timeout_spin.setSuffix("  seconds")
        self.scan_timeout_spin.setValue(self.settings.get("scan_timeout", 5))
        form.addRow("Scan Timeout:", self.scan_timeout_spin)

        # Thread count
        self.thread_count_spin = QSpinBox()
        self.thread_count_spin.setRange(1, 256)
        self.thread_count_spin.setValue(self.settings.get("thread_count", 50))
        form.addRow("Default Threads:", self.thread_count_spin)

        # Alert sound
        self.alert_sound_chk = QCheckBox("Enable alert sounds")
        self.alert_sound_chk.setChecked(self.settings.get("alert_sound", True))
        form.addRow("Alerts:", self.alert_sound_chk)

        # Log retention
        self.log_retention_spin = QSpinBox()
        self.log_retention_spin.setRange(1, 365)
        self.log_retention_spin.setSuffix("  days")
        self.log_retention_spin.setValue(self.settings.get("log_retention_days", 30))
        form.addRow("Log Retention:", self.log_retention_spin)

        layout.addLayout(form)
        layout.addStretch()

        # Dialog buttons
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.setStyleSheet(
            f"""
            QPushButton {{
                min-width: 90px;
                padding: 8px 20px;
            }}
            """
        )
        btn_box.accepted.connect(self._accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    # -------------------------------------------------------------- accept
    def _accept(self) -> None:
        self.settings["scan_timeout"] = self.scan_timeout_spin.value()
        self.settings["thread_count"] = self.thread_count_spin.value()
        self.settings["alert_sound"] = self.alert_sound_chk.isChecked()
        self.settings["log_retention_days"] = self.log_retention_spin.value()
        self.accept()


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                         Main Window                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class MainWindow(QMainWindow):
    """Top-level application window – owns every tab and every core thread."""

    # Navigation items: (emoji, label)
    NAV_ITEMS = [
        ("📊", "Dashboard"),
        ("🖥️", "Hosts"),
        ("🛡️", "ARP Monitor"),
        ("🌐", "DNS Monitor"),
        ("📦", "Packets"),
        ("🔍", "Port Scanner"),
        ("📡", "DHCP Detector"),
        ("🔒", "SSL Inspector"),
        ("🕷️", "MITM Detector"),
        ("📋", "Logs"),
    ]

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetWraith | Network Security Analyzer")
        self.setMinimumSize(1280, 780)
        self.resize(1440, 880)

        # ---- state ----------------------------------------------------------
        self._monitoring = False
        self._packet_count = 0
        self._alert_count = 0
        self._active_threads: list = []
        self._settings: dict = {
            "scan_timeout": 5,
            "thread_count": 50,
            "alert_sound": True,
            "log_retention_days": 30,
        }

        # Thread references (created on demand, kept alive while running)
        self._scanner_thread: Optional[ScannerThread] = None
        self._arp_thread: Optional[ARPMonitorThread] = None
        self._dns_thread: Optional[DNSSnifferThread] = None
        self._packet_thread: Optional[PacketCaptureThread] = None
        self._port_scanner_thread: Optional[PortScannerThread] = None
        self._dhcp_thread: Optional[DHCPWatcherThread] = None
        self._ssl_thread: Optional[SSLInspectorThread] = None
        self._mitm_thread: Optional[MITMDetectorThread] = None

        # ---- Build the UI ---------------------------------------------------
        self._build_menu_bar()
        self._build_central_area()
        self._build_status_bar()
        self._setup_system_tray()
        self._setup_shortcuts()
        self._detect_interfaces()
        self._wire_signals()

        # Periodic status-bar updater (every 1 s)
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_timer.start(1000)

    # ==================================================================== #
    #                         UI CONSTRUCTION                                #
    # ==================================================================== #

    # ---- Menu Bar --------------------------------------------------------
    def _build_menu_bar(self) -> None:
        mb = self.menuBar()

        # File
        file_menu = mb.addMenu("&File")
        export_act = QAction("Export Logs…", self)
        export_act.setShortcut(QKeySequence("Ctrl+S"))
        export_act.triggered.connect(self._export_logs)
        file_menu.addAction(export_act)
        file_menu.addSeparator()
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self._real_quit)
        file_menu.addAction(exit_act)

        # Tools
        tools_menu = mb.addMenu("&Tools")
        settings_act = QAction("Settings…", self)
        settings_act.triggered.connect(self._open_settings)
        tools_menu.addAction(settings_act)

        # Help
        help_menu = mb.addMenu("&Help")
        about_act = QAction("About NetWraith", self)
        about_act.triggered.connect(self._show_about)
        help_menu.addAction(about_act)

    # ---- Central Area (toolbar + sidebar + stacked tabs) ----------------
    def _build_central_area(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Top toolbar ──────────────────────────────────────────────────
        toolbar = QFrame()
        toolbar.setFixedHeight(56)
        toolbar.setStyleSheet(
            f"QFrame {{ background-color: {BG_PANEL}; border-bottom: 1px solid {BORDER_COLOR}; }}"
        )
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(14, 0, 14, 0)
        tb_layout.setSpacing(10)

        # Interface selector
        iface_label = QLabel("Interface:")
        iface_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-weight: bold; background: transparent;")
        tb_layout.addWidget(iface_label)
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(260)
        self.iface_combo.currentIndexChanged.connect(self._on_interface_changed)
        tb_layout.addWidget(self.iface_combo)

        # IP range
        range_label = QLabel("IP Range:")
        range_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-weight: bold; background: transparent;")
        tb_layout.addWidget(range_label)
        self.range_edit = QLineEdit()
        self.range_edit.setPlaceholderText("e.g. 192.168.1.0/24")
        self.range_edit.setFixedWidth(180)
        tb_layout.addWidget(self.range_edit)

        # Start / Stop button
        self.monitor_btn = QPushButton("▶  Start Monitoring")
        self.monitor_btn.setFixedWidth(190)
        self.monitor_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._style_monitor_button(False)
        self.monitor_btn.clicked.connect(self._toggle_monitoring)
        tb_layout.addWidget(self.monitor_btn)

        tb_layout.addStretch()

        # Live packet counter badge
        self.packet_badge = QLabel("  0 pkts  ")
        self.packet_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.packet_badge.setStyleSheet(
            f"""
            QLabel {{
                background-color: {ACCENT_CYAN};
                color: {BG_DARK};
                font-weight: bold;
                font-size: 12px;
                border-radius: 10px;
                padding: 3px 14px;
            }}
            """
        )
        tb_layout.addWidget(self.packet_badge)

        root_layout.addWidget(toolbar)

        # ── Body (sidebar + stacked widget) ──────────────────────────────
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Sidebar
        sidebar = self._build_sidebar()
        body_layout.addWidget(sidebar)

        # Stacked tabs
        self.stack = QStackedWidget()
        self.stack.setStyleSheet(f"QStackedWidget {{ background-color: {BG_DARK}; }}")

        self.dashboard_tab = DashboardTab()
        self.hosts_tab = HostsTab()
        self.arp_tab = ARPTab()
        self.dns_tab = DNSTab()
        self.packets_tab = PacketsTab()
        self.ports_tab = PortsTab()
        self.dhcp_tab = DHCPTab()
        self.ssl_tab = SSLTab()
        self.mitm_tab = MITMTab()
        self.logs_tab = LogsTab()

        self.stack.addWidget(self.dashboard_tab)   # 0
        self.stack.addWidget(self.hosts_tab)        # 1
        self.stack.addWidget(self.arp_tab)          # 2
        self.stack.addWidget(self.dns_tab)          # 3
        self.stack.addWidget(self.packets_tab)      # 4
        self.stack.addWidget(self.ports_tab)        # 5
        self.stack.addWidget(self.dhcp_tab)         # 6
        self.stack.addWidget(self.ssl_tab)          # 7
        self.stack.addWidget(self.mitm_tab)         # 8
        self.stack.addWidget(self.logs_tab)         # 9

        body_layout.addWidget(self.stack)
        root_layout.addWidget(body, stretch=1)

    # ---- Sidebar ---------------------------------------------------------
    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setFixedWidth(210)
        sidebar.setStyleSheet(
            f"""
            QFrame {{
                background-color: {BG_PANEL};
                border-right: 1px solid {BORDER_COLOR};
            }}
            """
        )
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(2)

        # Logo / brand label
        brand = QLabel("  🕸️  NetWraith")
        brand.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        brand.setStyleSheet(
            f"color: {ACCENT_CYAN}; padding: 10px 8px 18px 8px; background: transparent;"
        )
        layout.addWidget(brand)

        # Navigation buttons
        self._nav_buttons: list[QPushButton] = []
        for idx, (emoji, label) in enumerate(self.NAV_ITEMS):
            btn = QPushButton(f"  {emoji}  {label}")
            btn.setFont(QFont("Segoe UI", 11))
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedHeight(40)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=idx: self._switch_tab(i))
            self._nav_buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # Author label at bottom
        ver_label = QLabel("  by Taezeem Tariq")
        ver_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; padding: 6px; background: transparent;")
        layout.addWidget(ver_label)

        # Highlight first tab
        self._switch_tab(0)

        return sidebar

    def _switch_tab(self, index: int) -> None:
        """Switch stacked widget and update sidebar button styles."""
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            if i == index:
                btn.setStyleSheet(
                    f"""
                    QPushButton {{
                        background-color: rgba(0, 229, 255, 0.08);
                        color: {ACCENT_CYAN};
                        border: none;
                        border-left: 3px solid {ACCENT_CYAN};
                        text-align: left;
                        padding-left: 12px;
                        font-weight: bold;
                    }}
                    """
                )
                btn.setChecked(True)
            else:
                btn.setStyleSheet(
                    f"""
                    QPushButton {{
                        background-color: transparent;
                        color: {TEXT_SECONDARY};
                        border: none;
                        border-left: 3px solid transparent;
                        text-align: left;
                        padding-left: 12px;
                    }}
                    QPushButton:hover {{
                        background-color: rgba(255,255,255,0.04);
                        color: {TEXT_PRIMARY};
                    }}
                    """
                )
                btn.setChecked(False)

    # ---- Status Bar ------------------------------------------------------
    def _build_status_bar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)

        self.sb_iface_label = QLabel("Interface: —")
        self.sb_iface_label.setStyleSheet(f"color: {TEXT_SECONDARY}; padding: 0 8px; background: transparent;")
        sb.addWidget(self.sb_iface_label)

        sb.addWidget(self._separator_label())

        self.sb_ip_label = QLabel("Local IP: —")
        self.sb_ip_label.setStyleSheet(f"color: {TEXT_SECONDARY}; padding: 0 8px; background: transparent;")
        sb.addWidget(self.sb_ip_label)

        sb.addWidget(self._separator_label())

        self.sb_gw_label = QLabel("Gateway: —")
        self.sb_gw_label.setStyleSheet(f"color: {TEXT_SECONDARY}; padding: 0 8px; background: transparent;")
        sb.addWidget(self.sb_gw_label)

        sb.addWidget(self._separator_label())

        self.sb_packets_label = QLabel("Packets: 0")
        self.sb_packets_label.setStyleSheet(f"color: {ACCENT_CYAN}; font-weight: bold; padding: 0 8px; background: transparent;")
        sb.addWidget(self.sb_packets_label)

        sb.addWidget(self._separator_label())

        self.sb_alerts_label = QLabel("Alerts: 0")
        self.sb_alerts_label.setStyleSheet(f"color: {DANGER_RED}; font-weight: bold; padding: 0 8px; background: transparent;")
        sb.addWidget(self.sb_alerts_label)

    @staticmethod
    def _separator_label() -> QLabel:
        sep = QLabel("|")
        sep.setStyleSheet(f"color: {BORDER_COLOR}; padding: 0 2px; background: transparent;")
        return sep

    def _update_status_bar(self) -> None:
        self.sb_packets_label.setText(f"Packets: {self._packet_count}")
        self.sb_alerts_label.setText(f"Alerts: {self._alert_count}")
        self.packet_badge.setText(f"  {self._packet_count} pkts  ")

    # ==================================================================== #
    #                      NETWORK DETECTION                                 #
    # ==================================================================== #

    def _detect_interfaces(self) -> None:
        """Populate the interface combo box using netifaces or socket/scapy fallbacks."""
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()

        if not HAS_NETIFACES:
            # Robust fallback: use socket and scapy to find local interfaces/IPs
            try:
                ips = []
                # Try getting addresses using socket.gethostbyname_ex
                try:
                    hostname = socket.gethostname()
                    for ip in socket.gethostbyname_ex(hostname)[2]:
                        if not ip.startswith("127.") and ip not in ips:
                            ips.append(ip)
                except Exception:
                    pass

                # Try getting interfaces from Scapy
                try:
                    import scapy.all as scapy_all
                    for iface_name in scapy_all.get_if_list():
                        try:
                            ip = scapy_all.get_if_addr(iface_name)
                            if ip and ip != "127.0.0.1" and ip not in ips:
                                ips.append(ip)
                        except Exception:
                            pass
                except Exception:
                    pass

                if ips:
                    for i, ip in enumerate(ips):
                        # Attempt to auto-name the fallback interface (e.g. eth0, wlan0)
                        iface_id = f"eth{i}"
                        self.iface_combo.addItem(
                            f"Interface {i} ({ip})",
                            {"iface": iface_id, "ip": ip, "netmask": "255.255.255.0"}
                        )
                else:
                    self.iface_combo.addItem(
                        "localhost — 127.0.0.1",
                        {"iface": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0"}
                    )
            except Exception as exc:
                logger.error("Fallback interface detection failed: %s", exc)
                self.iface_combo.addItem(
                    "localhost — 127.0.0.1",
                    {"iface": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0"}
                )

            self.iface_combo.blockSignals(False)
            self._on_interface_changed(0)
            return

        try:
            for iface_name in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface_name)
                ipv4_list = addrs.get(netifaces.AF_INET, [])
                for info in ipv4_list:
                    ip = info.get("addr", "")
                    netmask = info.get("netmask", "255.255.255.0")
                    if ip and ip != "127.0.0.1":
                        display = f"{iface_name} — {ip}"
                        self.iface_combo.addItem(
                            display,
                            {"iface": iface_name, "ip": ip, "netmask": netmask},
                        )
        except Exception as exc:
            logger.error("Interface detection failed: %s", exc)

        # Fallback if nothing usable found
        if self.iface_combo.count() == 0:
            self.iface_combo.addItem("No interfaces detected", {"iface": "", "ip": "0.0.0.0", "netmask": "255.255.255.0"})

        self.iface_combo.blockSignals(False)
        self._on_interface_changed(0)

    def _on_interface_changed(self, index: int) -> None:
        """Update range edit and status bar when the user picks an interface."""
        data = self.iface_combo.currentData()
        if not data:
            return
        ip = data.get("ip", "0.0.0.0")
        netmask = data.get("netmask", "255.255.255.0")
        iface_name = data.get("iface", "")

        subnet = self._get_subnet(ip, netmask)
        self.range_edit.setText(subnet)

        gateway = self._get_gateway()

        self.sb_iface_label.setText(f"Interface: {iface_name}")
        self.sb_ip_label.setText(f"Local IP: {ip}")
        self.sb_gw_label.setText(f"Gateway: {gateway}")

    def _get_subnet(self, ip: str, netmask: str) -> str:
        """Calculate CIDR subnet from IP + netmask."""
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception:
            return f"{ip}/24"

    def _get_gateway(self) -> str:
        """Return the default gateway IP using netifaces or scapy fallback."""
        if not HAS_NETIFACES:
            try:
                import scapy.all as scapy_all
                route = scapy_all.conf.route.route("0.0.0.0")
                if route and len(route) > 2 and route[2] != "0.0.0.0":
                    return route[2]
            except Exception:
                pass
            return "Unknown"
        try:
            gateways = netifaces.gateways()
            default = gateways.get("default", {})
            ipv4_gw = default.get(netifaces.AF_INET)
            if ipv4_gw:
                return ipv4_gw[0]
        except Exception:
            pass
        return "Unknown"

    def _get_local_ip(self) -> str:
        """Return the local IP for the currently selected interface."""
        data = self.iface_combo.currentData()
        if data:
            return data.get("ip", "0.0.0.0")
        return "0.0.0.0"

    def _get_selected_iface(self) -> str:
        """Return the interface name currently selected."""
        data = self.iface_combo.currentData()
        if data:
            return data.get("iface", "")
        return ""

    # ==================================================================== #
    #                  MONITORING TOGGLE + THREAD MGMT                       #
    # ==================================================================== #

    def _toggle_monitoring(self) -> None:
        if self._monitoring:
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self) -> None:
        iface = self._get_selected_iface()
        if not iface:
            QMessageBox.warning(self, "No Interface", "Please select a valid network interface.")
            return

        self._monitoring = True
        self._style_monitor_button(True)
        self.monitor_btn.setText("⏹  Stop Monitoring")

        # Launch packet capture thread
        self._start_packet_capture(iface)

        logger.info("Monitoring started on %s", iface)

    def _stop_monitoring(self) -> None:
        self._monitoring = False
        self._style_monitor_button(False)
        self.monitor_btn.setText("▶  Start Monitoring")
        self._stop_packet_capture()
        logger.info("Monitoring stopped")

    def _style_monitor_button(self, active: bool) -> None:
        if active:
            self.monitor_btn.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {DANGER_RED};
                    color: {TEXT_PRIMARY};
                    border: none;
                    border-radius: 6px;
                    font-weight: bold;
                    padding: 8px 18px;
                }}
                QPushButton:hover {{
                    background-color: #ff6b6b;
                }}
                """
            )
        else:
            self.monitor_btn.setStyleSheet(
                f"""
                QPushButton {{
                    background-color: {SUCCESS_GREEN};
                    color: {TEXT_PRIMARY};
                    border: none;
                    border-radius: 6px;
                    font-weight: bold;
                    padding: 8px 18px;
                }}
                QPushButton:hover {{
                    background-color: #66bb6a;
                }}
                """
            )

    # ---- Thread helpers --------------------------------------------------
    def _register_thread(self, thread) -> None:
        """Keep a reference so threads aren't garbage-collected."""
        if thread not in self._active_threads:
            self._active_threads.append(thread)
        thread.finished.connect(lambda t=thread: self._unregister_thread(t))

    def _unregister_thread(self, thread) -> None:
        try:
            self._active_threads.remove(thread)
        except ValueError:
            pass

    def stop_all_threads(self) -> None:
        """Gracefully stop every running thread."""
        for thread in list(self._active_threads):
            if hasattr(thread, "stop"):
                thread.stop()
        # Give threads a moment to finish
        for thread in list(self._active_threads):
            if thread.isRunning():
                thread.quit()
                thread.wait(3000)
        self._active_threads.clear()
        self._monitoring = False
        self._style_monitor_button(False)
        self.monitor_btn.setText("▶  Start Monitoring")

    # ==================================================================== #
    #                       SIGNAL WIRING                                    #
    # ==================================================================== #

    def _wire_signals(self) -> None:
        """Connect every tab's action signals to the corresponding core engine."""

        # 1 ── Hosts tab: scan_requested → ScannerThread
        if hasattr(self.hosts_tab, "scan_requested"):
            self.hosts_tab.scan_requested.connect(self._on_host_scan_requested)

        # 2 ── ARP tab: monitoring_toggled → ARPMonitorThread
        if hasattr(self.arp_tab, "monitoring_toggled"):
            self.arp_tab.monitoring_toggled.connect(self._on_arp_toggled)

        # 3 ── DNS tab: sniffing_toggled → DNSSnifferThread
        if hasattr(self.dns_tab, "sniffing_toggled"):
            self.dns_tab.sniffing_toggled.connect(self._on_dns_toggled)

        # 4 ── Packets tab: capture_toggled → PacketCaptureThread
        if hasattr(self.packets_tab, "capture_toggled"):
            self.packets_tab.capture_toggled.connect(self._on_packet_capture_toggled)

        # 5 ── Ports tab: scan_requested → PortScannerThread
        if hasattr(self.ports_tab, "scan_requested"):
            self.ports_tab.scan_requested.connect(self._on_port_scan_requested)

        # 6 ── DHCP tab: monitoring_toggled → DHCPWatcherThread
        if hasattr(self.dhcp_tab, "monitoring_toggled"):
            self.dhcp_tab.monitoring_toggled.connect(self._on_dhcp_toggled)

        # 7 ── SSL tab: inspect_requested → SSLInspectorThread
        if hasattr(self.ssl_tab, "inspect_requested"):
            self.ssl_tab.inspect_requested.connect(self._on_ssl_inspect_requested)

        # 8 ── MITM tab: detection_toggled → MITMDetectorThread
        if hasattr(self.mitm_tab, "detection_toggled"):
            self.mitm_tab.detection_toggled.connect(self._on_mitm_toggled)

        # ARP Tab baseline snapshot requested
        if hasattr(self.arp_tab, "baseline_requested"):
            self.arp_tab.baseline_requested.connect(self._on_arp_baseline_requested)

        # 9 ── Dashboard quick-action buttons
        if hasattr(self.dashboard_tab, "action_arp_scan"):
            self.dashboard_tab.action_arp_scan.connect(self._dashboard_quick_scan)
        if hasattr(self.dashboard_tab, "action_dns_sniff"):
            self.dashboard_tab.action_dns_sniff.connect(self._dashboard_quick_dns)
        if hasattr(self.dashboard_tab, "action_port_scan"):
            self.dashboard_tab.action_port_scan.connect(self._dashboard_quick_port_scan)

    # ────────────────────────────── 1. Host Scan ──────────────────────────
    @pyqtSlot(str)
    def _on_host_scan_requested(self, target: str) -> None:
        """Launch a network host scan."""
        if self._scanner_thread and self._scanner_thread.isRunning():
            self._scanner_thread.stop()
            self._scanner_thread.wait(2000)

        ip_range = target if target else self.range_edit.text().strip()
        if not ip_range:
            return

        iface = self._get_selected_iface()
        self._scanner_thread = ScannerThread(ip_range, iface, timeout=self._settings["scan_timeout"])
        self._register_thread(self._scanner_thread)

        # Wire scanner signals
        if hasattr(self._scanner_thread, "host_found"):
            self._scanner_thread.host_found.connect(self.hosts_tab.add_host)
        if hasattr(self._scanner_thread, "scan_complete"):
            self._scanner_thread.scan_complete.connect(self._on_host_scan_complete)
        if hasattr(self._scanner_thread, "error_signal"):
            self._scanner_thread.error_signal.connect(self._on_engine_error)
        if hasattr(self._scanner_thread, "progress"):
            if hasattr(self.hosts_tab, "update_progress"):
                self._scanner_thread.progress.connect(self.hosts_tab.update_progress)

        self._scanner_thread.start()

    @pyqtSlot()
    def _on_host_scan_complete(self) -> None:
        self._add_log("INFO", "Host scan completed.")
        if hasattr(self.dashboard_tab, "update_host_count"):
            host_count = 0
            if hasattr(self.hosts_tab, "get_host_count"):
                host_count = self.hosts_tab.get_host_count()
            self.dashboard_tab.update_host_count(host_count)

    # ────────────────────────────── 2. ARP Monitor ───────────────────────
    @pyqtSlot(bool)
    def _on_arp_toggled(self, start: bool) -> None:
        if start:
            iface = self._get_selected_iface()
            self._arp_thread = ARPMonitorThread(iface)
            self._register_thread(self._arp_thread)
            
            # Load baseline from trusted_hosts.json
            baseline_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "trusted_hosts.json")
            hosts = {}
            if os.path.isfile(baseline_path):
                try:
                    with open(baseline_path, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        hosts = {ip: h.get("mac", "") for ip, h in data.items() if "mac" in h}
                    elif isinstance(data, list):
                        hosts = {h["ip"]: h.get("mac", "") for h in data if "ip" in h and "mac" in h}
                except Exception as exc:
                    logger.warning("Could not load trusted hosts for ARP monitor baseline: %s", exc)
            self._arp_thread.set_baseline(hosts)

            if hasattr(self._arp_thread, "arp_alert"):
                self._arp_thread.arp_alert.connect(self._on_arp_alert)
            if hasattr(self._arp_thread, "arp_packet"):
                if hasattr(self.arp_tab, "add_arp_entry"):
                    self._arp_thread.arp_packet.connect(self.arp_tab.add_arp_entry)
            if hasattr(self._arp_thread, "error_signal"):
                self._arp_thread.error_signal.connect(self._on_engine_error)
            self._arp_thread.start()
        else:
            if self._arp_thread and self._arp_thread.isRunning():
                self._arp_thread.stop()

    @pyqtSlot(dict)
    def _on_arp_alert(self, alert_data: dict) -> None:
        msg = alert_data.get("message", "ARP anomaly detected")
        self._increment_alert()
        if hasattr(self.arp_tab, "add_alert"):
            self.arp_tab.add_alert(alert_data)
        self._add_log("ALERT", msg)
        self._tray_notify("ARP Alert", msg)

    @pyqtSlot()
    def _on_arp_baseline_requested(self) -> None:
        if self._arp_thread and self._arp_thread.isRunning():
            baseline_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "trusted_hosts.json")
            hosts = {}
            if os.path.isfile(baseline_path):
                try:
                    with open(baseline_path, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        hosts = {ip: h.get("mac", "") for ip, h in data.items() if "mac" in h}
                    elif isinstance(data, list):
                        hosts = {h["ip"]: h.get("mac", "") for h in data if "ip" in h and "mac" in h}
                except Exception as exc:
                    logger.warning("Could not load trusted hosts for ARP monitor baseline: %s", exc)
            self._arp_thread.set_baseline(hosts)
            self._add_log("INFO", "ARP Monitor baseline reloaded on the fly.")

    # ────────────────────────────── 3. DNS Sniffer ───────────────────────
    @pyqtSlot(bool)
    def _on_dns_toggled(self, start: bool) -> None:
        if start:
            iface = self._get_selected_iface()
            self._dns_thread = DNSSnifferThread(iface)
            self._register_thread(self._dns_thread)
            if hasattr(self._dns_thread, "dns_query"):
                if hasattr(self.dns_tab, "add_dns_entry"):
                    self._dns_thread.dns_query.connect(self.dns_tab.add_dns_entry)
            if hasattr(self._dns_thread, "dns_anomaly"):
                self._dns_thread.dns_anomaly.connect(self._on_dns_anomaly)
            if hasattr(self._dns_thread, "error_signal"):
                self._dns_thread.error_signal.connect(self._on_engine_error)
            self._dns_thread.start()
        else:
            if self._dns_thread and self._dns_thread.isRunning():
                self._dns_thread.stop()

    @pyqtSlot(dict)
    def _on_dns_anomaly(self, data: dict) -> None:
        msg = data.get("message", "DNS anomaly detected")
        self._increment_alert()
        self._add_log("ALERT", msg)
        self._tray_notify("DNS Alert", msg)

    # ────────────────────────────── 4. Packet Capture ────────────────────
    @pyqtSlot(bool)
    def _on_packet_capture_toggled(self, start: bool) -> None:
        if start:
            self._start_packet_capture(self._get_selected_iface())
        else:
            self._stop_packet_capture()

    def _start_packet_capture(self, iface: str) -> None:
        if self._packet_thread and self._packet_thread.isRunning():
            return  # already running
        self._packet_thread = PacketCaptureThread(iface)
        self._register_thread(self._packet_thread)
        if hasattr(self._packet_thread, "packet_captured"):
            self._packet_thread.packet_captured.connect(self._on_packet_captured)
        if hasattr(self._packet_thread, "error_signal"):
            self._packet_thread.error_signal.connect(self._on_engine_error)
        self._packet_thread.start()

    def _stop_packet_capture(self) -> None:
        if self._packet_thread and self._packet_thread.isRunning():
            self._packet_thread.stop()

    @pyqtSlot(dict)
    def _on_packet_captured(self, pkt_data: dict) -> None:
        self._packet_count += 1
        # Map src_ip -> src, dst_ip -> dst to match PacketsTab keys
        if "src_ip" in pkt_data:
            pkt_data["src"] = pkt_data["src_ip"]
        if "dst_ip" in pkt_data:
            pkt_data["dst"] = pkt_data["dst_ip"]
        
        # Get detailed layer breakdown
        if self._packet_thread:
            idx = pkt_data.get("number", self._packet_count) - 1
            pkt_data["detail"] = self._packet_thread.get_packet_detail(idx)

        if hasattr(self.packets_tab, "add_packet"):
            self.packets_tab.add_packet(pkt_data)
        if hasattr(self.dashboard_tab, "update_packet_count"):
            self.dashboard_tab.update_packet_count(self._packet_count)

    # ────────────────────────────── 5. Port Scanner ──────────────────────
    @pyqtSlot(str, tuple, str, int)
    def _on_port_scan_requested(self, target: str, port_range: tuple[int, int], scan_type: str, threads: int) -> None:
        if self._port_scanner_thread and self._port_scanner_thread.isRunning():
            self._port_scanner_thread.stop()
            self._port_scanner_thread.wait(2000)

        # Convert scan_type to the format expected by the backend engine (lowercase with underscores)
        # Tab sends "TCP Connect", "SYN Scan", "UDP Scan"
        engine_type = "tcp_connect"
        t_lower = scan_type.lower()
        if "syn" in t_lower:
            engine_type = "syn"
        elif "udp" in t_lower:
            engine_type = "udp"

        self._port_scanner_thread = PortScannerThread(
            target_ip=target,
            port_range=port_range,
            scan_type=engine_type,
            thread_count=threads
        )
        self._register_thread(self._port_scanner_thread)
        if hasattr(self._port_scanner_thread, "port_result"):
            if hasattr(self.ports_tab, "add_port_result"):
                self._port_scanner_thread.port_result.connect(self.ports_tab.add_port_result)
        if hasattr(self._port_scanner_thread, "scan_progress"):
            if hasattr(self.ports_tab, "set_progress"):
                self._port_scanner_thread.scan_progress.connect(self.ports_tab.set_progress)
        if hasattr(self._port_scanner_thread, "scan_complete"):
            self._port_scanner_thread.scan_complete.connect(self._on_port_scan_complete)
        if hasattr(self._port_scanner_thread, "error_signal"):
            self._port_scanner_thread.error_signal.connect(self._on_engine_error)
        self._port_scanner_thread.start()

    def _on_port_scan_complete(self, results: list) -> None:
        self._add_log("INFO", "Port scan completed.")
        if hasattr(self.ports_tab, "set_scanning"):
            self.ports_tab.set_scanning(False)

    # ────────────────────────────── 6. DHCP Watcher ──────────────────────
    @pyqtSlot(bool)
    def _on_dhcp_toggled(self, start: bool) -> None:
        if start:
            iface = self._get_selected_iface()
            self._dhcp_thread = DHCPWatcherThread(iface)
            self._register_thread(self._dhcp_thread)
            if hasattr(self._dhcp_thread, "dhcp_event"):
                if hasattr(self.dhcp_tab, "add_dhcp_event"):
                    self._dhcp_thread.dhcp_event.connect(self.dhcp_tab.add_dhcp_event)
            if hasattr(self._dhcp_thread, "rogue_alert"):
                self._dhcp_thread.rogue_alert.connect(self._on_dhcp_rogue_alert)
            if hasattr(self._dhcp_thread, "error_signal"):
                self._dhcp_thread.error_signal.connect(self._on_engine_error)
            self._dhcp_thread.start()
        else:
            if self._dhcp_thread and self._dhcp_thread.isRunning():
                self._dhcp_thread.stop()

    @pyqtSlot(dict)
    def _on_dhcp_rogue_alert(self, data: dict) -> None:
        msg = data.get("description", "Rogue DHCP server detected!")
        self._increment_alert()
        self._add_log("CRITICAL", msg)
        self._tray_notify("DHCP Alert", msg)
        if hasattr(self.dhcp_tab, "add_alert"):
            # Prepare alert dictionary format expected by DHCPTab.add_alert
            alert_formatted = {
                "timestamp": data.get("timestamp", datetime.now().strftime("%H:%M:%S")),
                "severity": "CRITICAL",
                "message": msg
            }
            self.dhcp_tab.add_alert(alert_formatted)

    # ────────────────────────────── 7. SSL Inspector ─────────────────────
    @pyqtSlot(list)
    def _on_ssl_inspect_requested(self, targets: list[str]) -> None:
        if self._ssl_thread and self._ssl_thread.isRunning():
            self._ssl_thread.stop()
            self._ssl_thread.wait(2000)

        self._ssl_thread = SSLInspectorThread(targets)
        self._register_thread(self._ssl_thread)
        if hasattr(self._ssl_thread, "cert_result"):
            if hasattr(self.ssl_tab, "add_cert_result"):
                self._ssl_thread.cert_result.connect(self.ssl_tab.add_cert_result)
        if hasattr(self._ssl_thread, "error_signal"):
            self._ssl_thread.error_signal.connect(self._on_engine_error)
        self._ssl_thread.start()

    # ────────────────────────────── 8. MITM Detector ─────────────────────
    @pyqtSlot(bool)
    def _on_mitm_toggled(self, start: bool) -> None:
        if start:
            iface = self._get_selected_iface()
            gateway_ip = self._get_gateway()
            self._mitm_thread = MITMDetectorThread(iface, gateway_ip)
            self._register_thread(self._mitm_thread)
            if hasattr(self._mitm_thread, "mitm_alert"):
                self._mitm_thread.mitm_alert.connect(self._on_mitm_alert)
            if hasattr(self._mitm_thread, "status_update"):
                if hasattr(self.mitm_tab, "update_status"):
                    self._mitm_thread.status_update.connect(self.mitm_tab.update_status)
            if hasattr(self._mitm_thread, "error_signal"):
                self._mitm_thread.error_signal.connect(self._on_engine_error)
            self._mitm_thread.start()
        else:
            if self._mitm_thread and self._mitm_thread.isRunning():
                self._mitm_thread.stop()

    @pyqtSlot(dict)
    def _on_mitm_alert(self, data: dict) -> None:
        msg = data.get("message", "Potential MITM attack detected!")
        self._increment_alert()
        if hasattr(self.mitm_tab, "add_alert"):
            self.mitm_tab.add_alert(data)
        self._add_log("CRITICAL", msg)
        self._tray_notify("MITM Alert ⚠️", msg)

    # ────────────────────────────── Engine error handler ──────────────────
    @pyqtSlot(str)
    def _on_engine_error(self, error_msg: str) -> None:
        self._add_log("ERROR", error_msg)
        logger.error("Engine error: %s", error_msg)

    # ────────────────────────────── Dashboard quick-actions ───────────────
    def _dashboard_quick_scan(self) -> None:
        self._switch_tab(1)  # switch to Hosts
        ip_range = self.range_edit.text().strip()
        if ip_range:
            self._on_host_scan_requested(ip_range)

    def _dashboard_quick_dns(self) -> None:
        self._switch_tab(3)  # switch to DNS Monitor
        if hasattr(self.dns_tab, "set_monitoring"):
            self.dns_tab.set_monitoring(True)
        self._on_dns_toggled(True)

    def _dashboard_quick_port_scan(self) -> None:
        self._switch_tab(5)  # switch to Ports Tab

    # ==================================================================== #
    #                      LOGGING / ALERT HELPERS                           #
    # ==================================================================== #

    def _add_log(self, level: str, message: str) -> None:
        """Route a message to the Logs tab and optionally persist to disk."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"timestamp": timestamp, "level": level, "message": message}
        if hasattr(self.logs_tab, "add_log_entry"):
            self.logs_tab.add_log_entry(entry)

        # Persist critical entries
        if level in ("ALERT", "CRITICAL", "ERROR"):
            self._persist_alert(entry)

    def _persist_alert(self, entry: dict) -> None:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "alerts.log")
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{entry['timestamp']}] [{entry['level']}] {entry['message']}\n")
        except Exception as exc:
            logger.error("Failed to persist alert: %s", exc)

    def _increment_alert(self) -> None:
        self._alert_count += 1
        if hasattr(self.dashboard_tab, "update_alert_count"):
            self.dashboard_tab.update_alert_count(self._alert_count)

    # ==================================================================== #
    #                       SYSTEM TRAY                                      #
    # ==================================================================== #

    def _setup_system_tray(self) -> None:
        self._tray_icon = QSystemTrayIcon(self)
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.png")
        if os.path.isfile(icon_path):
            self._tray_icon.setIcon(QIcon(icon_path))
        else:
            # Fallback to application icon
            self._tray_icon.setIcon(self.windowIcon() if not self.windowIcon().isNull() else QIcon())
        self._tray_icon.setToolTip("NetWraith")

        tray_menu = QMenu(self)
        show_action = QAction("Show / Hide", self)
        show_action.triggered.connect(self._toggle_visibility)
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self._real_quit)
        tray_menu.addAction(exit_action)

        self._tray_icon.setContextMenu(tray_menu)
        self._tray_icon.activated.connect(self._on_tray_activated)
        self._tray_icon.show()

    def _toggle_visibility(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.activateWindow()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._toggle_visibility()

    def _tray_notify(self, title: str, message: str) -> None:
        """Show a tray notification bubble for critical alerts."""
        if self._tray_icon.isVisible():
            self._tray_icon.showMessage(
                title, message,
                QSystemTrayIcon.MessageIcon.Warning, 5000,
            )

    # ==================================================================== #
    #                     KEYBOARD SHORTCUTS                                 #
    # ==================================================================== #

    def _setup_shortcuts(self) -> None:
        # Ctrl+S — export logs (also in menu)
        # (handled by menu action already)

        # Ctrl+R — quick rescan hosts
        sc_rescan = QShortcut(QKeySequence("Ctrl+R"), self)
        sc_rescan.activated.connect(self._dashboard_quick_scan)

        # F5 — refresh hosts table
        sc_f5 = QShortcut(QKeySequence("F5"), self)
        sc_f5.activated.connect(self._dashboard_quick_scan)

        # Esc — stop all active captures/monitors
        sc_esc = QShortcut(QKeySequence("Escape"), self)
        sc_esc.activated.connect(self.stop_all_threads)

    # ==================================================================== #
    #                     MENU ACTIONS                                       #
    # ==================================================================== #

    def _export_logs(self) -> None:
        """Export all logs to a text file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", "netwraith_logs.txt",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return

        entries: list[dict] = []
        if hasattr(self.logs_tab, "get_all_entries"):
            entries = self.logs_tab.get_all_entries()

        try:
            if file_path.endswith(".json"):
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, default=str)
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    for e in entries:
                        ts = e.get("timestamp", "")
                        lvl = e.get("level", "INFO")
                        msg = e.get("message", "")
                        f.write(f"[{ts}] [{lvl}] {msg}\n")
            self._add_log("INFO", f"Logs exported to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self._settings, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._settings = dlg.settings
            self._add_log("INFO", "Settings updated.")

    def _show_about(self) -> None:
        banner_html = (
            "<pre style='font-family: \"Consolas\", \"Courier New\", monospace; color: #00e5ff; font-size: 11px; line-height: 1.2;'>"
            "      \\ (oo)_____/       # NetWraith\n"
            "        (__)     )\\\n"
            "            ||--||       [ Muhammad Taezeem Tariq Matta ]\n"
            "                         [ tg: t.me/Taezeem_14 ]\n"
            "                         [ github: taezeem14 ]"
            "</pre>"
        )
        QMessageBox.about(
            self,
            "About NetWraith",
            "<h2 style='color:#00e5ff;'>🕸️ NetWraith</h2>"
            "<p><b>Network Security Analyzer</b></p>"
            + banner_html +
            "<p style='color:#8a8f98;'>Real-time network monitoring, host discovery, "
            "ARP spoofing detection, DNS monitoring, packet capture, port scanning, "
            "DHCP rogue detection, SSL/TLS inspection, and MITM detection.</p>"
            "<hr>"
            "<p style='color:#ff4c4c;'>For authorized use only.</p>",
        )

    # ==================================================================== #
    #                     WINDOW LIFECYCLE                                   #
    # ==================================================================== #

    def closeEvent(self, event) -> None:  # noqa: N802
        """Minimise to tray instead of quitting (unless forced)."""
        if self._tray_icon.isVisible():
            self.hide()
            self._tray_icon.showMessage(
                "NetWraith",
                "Running in the system tray. Right-click → Exit to quit.",
                QSystemTrayIcon.MessageIcon.Information,
                2000,
            )
            event.ignore()
        else:
            self._real_quit()

    def _real_quit(self) -> None:
        """Stop everything and exit."""
        self.stop_all_threads()
        self._tray_icon.hide()
        QApplication.quit()
