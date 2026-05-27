"""
NetWraith — Dashboard Tab
=========================
Live overview dashboard with premium styled gradient metric cards, 
sparkline graph, alert logs, and glassmorphic action buttons.
"""

from collections import deque
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QListWidget,
    QListWidgetItem, QPushButton, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor

import pyqtgraph as pg

# ── Theme Constants ──────────────────────────────────────────────────────────
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

# ── Glassmorphic button styling ──
_BUTTON_STYLE = f"""
    QPushButton {{
        background-color: rgba(0, 229, 255, 0.05);
        color: {ACCENT_CYAN};
        border: 1px solid rgba(0, 229, 255, 0.15);
        border-radius: 8px;
        padding: 10px 18px;
        font-size: 13px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: rgba(0, 229, 255, 0.12);
        border-color: {ACCENT_CYAN};
        color: #ffffff;
    }}
    QPushButton:pressed {{
        background-color: rgba(0, 229, 255, 0.22);
    }}
"""

_PANEL_STYLE_ALERTS = f"""
    QFrame#AlertsPanel {{
        background-color: {BG_PANEL};
        border: 1px solid {BORDER_COLOR};
        border-radius: 12px;
    }}
    QLabel {{
        background: transparent;
        border: none;
    }}
"""

_PANEL_STYLE_ACTIONS = f"""
    QFrame#ActionsPanel {{
        background-color: {BG_PANEL};
        border: 1px solid {BORDER_COLOR};
        border-radius: 12px;
    }}
    QLabel {{
        background: transparent;
        border: none;
    }}
"""

_HEADER_LABEL_STYLE = f"color: {ACCENT_CYAN}; font-size: 14px; font-weight: bold; background: transparent; border: none; padding-bottom: 2px;"


# ═══════════════════════════════════════════════════════════════════════════════
#  Metric Card Widget
# ═══════════════════════════════════════════════════════════════════════════════
class _MetricCard(QFrame):
    """Single metric card showing icon, label, value, and trend."""

    def __init__(self, icon: str, label: str, bg_gradient: str, border_color: str, initial_value: str = "0", parent=None):
        super().__init__(parent)
        self.setObjectName("MetricCard")
        
        # Prevent stylesheets from cascading and breaking child QLabel elements
        self.setStyleSheet(f"""
            QFrame#MetricCard {{
                background: {bg_gradient};
                border: 1px solid {border_color};
                border-radius: 12px;
            }}
            QLabel {{
                background: transparent;
                border: none;
                padding: 0;
            }}
        """)
        self.setMinimumHeight(115)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        # Row 1: icon + label
        top_row = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 18))
        top_row.addWidget(icon_lbl)

        name_lbl = QLabel(label)
        name_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
        name_lbl.setStyleSheet(f"color: {TEXT_SECONDARY};")
        top_row.addWidget(name_lbl)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Row 2: value + trend
        val_row = QHBoxLayout()
        self._value_lbl = QLabel(initial_value)
        self._value_lbl.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        self._value_lbl.setStyleSheet(f"color: {TEXT_PRIMARY};")
        val_row.addWidget(self._value_lbl)

        self._trend_lbl = QLabel("")
        self._trend_lbl.setFont(QFont("Segoe UI", 12))
        self._trend_lbl.setStyleSheet(f"color: {SUCCESS_GREEN};")
        val_row.addWidget(self._trend_lbl, alignment=Qt.AlignmentFlag.AlignBottom)
        val_row.addStretch()
        layout.addLayout(val_row)

    def set_value(self, value: str, trend: str = "", trend_color: str = SUCCESS_GREEN):
        self._value_lbl.setText(value)
        self._trend_lbl.setText(trend)
        self._trend_lbl.setStyleSheet(f"color: {trend_color};")


# ═══════════════════════════════════════════════════════════════════════════════
#  Dashboard Tab
# ═══════════════════════════════════════════════════════════════════════════════
class DashboardTab(QWidget):
    """Live overview dashboard for NetWraith."""

    # Quick-action signals
    action_arp_scan = pyqtSignal()
    action_dns_sniff = pyqtSignal()
    action_port_scan = pyqtSignal()

    MAX_SPARKLINE_POINTS = 60  # 60 seconds rolling window

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packet_data: deque[float] = deque(maxlen=self.MAX_SPARKLINE_POINTS)
        for _ in range(self.MAX_SPARKLINE_POINTS):
            self._packet_data.append(0.0)
        self.setup_ui()

    # ── UI Construction ──────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(14)

        # ── Top row: metric cards ──
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(14)

        # Premium styled custom gradients and borders for each metric card
        self._card_hosts = _MetricCard(
            "🖥️", "Active Hosts",
            "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #112735, stop:1 #0c1a24)",
            "rgba(0, 229, 255, 0.45)"
        )
        self._card_pps = _MetricCard(
            "📦", "Packets/sec",
            "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a2335, stop:1 #101621)",
            "rgba(79, 195, 247, 0.45)"
        )
        self._card_alerts = _MetricCard(
            "⚠️", "Alerts Today",
            "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2b1f24, stop:1 #1a1216)",
            "rgba(255, 76, 76, 0.45)"
        )
        self._card_ports = _MetricCard(
            "🔍", "Open Ports",
            "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #251d35, stop:1 #171221)",
            "rgba(187, 134, 252, 0.45)"
        )

        for card in (self._card_hosts, self._card_pps, self._card_alerts, self._card_ports):
            cards_layout.addWidget(card)
        root.addLayout(cards_layout)

        # ── Middle: sparkline graph ──
        self._plot_widget = pg.PlotWidget()
        self._plot_widget.setBackground(BG_DARK)
        self._plot_widget.setMinimumHeight(200)
        self._plot_widget.showGrid(x=True, y=True, alpha=0.15)
        self._plot_widget.setLabel("left", "Packets/sec", color=TEXT_SECONDARY, size="10pt")
        self._plot_widget.setLabel("bottom", "Time (s)", color=TEXT_SECONDARY, size="10pt")
        self._plot_widget.getAxis("left").setPen(pg.mkPen(color=BORDER_COLOR))
        self._plot_widget.getAxis("bottom").setPen(pg.mkPen(color=BORDER_COLOR))
        self._plot_widget.getAxis("left").setTextPen(pg.mkPen(color=TEXT_SECONDARY))
        self._plot_widget.getAxis("bottom").setTextPen(pg.mkPen(color=TEXT_SECONDARY))
        self._plot_widget.setMouseEnabled(x=False, y=False)
        self._plot_widget.hideButtons()

        pen = pg.mkPen(color=ACCENT_CYAN, width=2)
        self._sparkline_curve = self._plot_widget.plot(
            list(range(-self.MAX_SPARKLINE_POINTS + 1, 1)),
            list(self._packet_data),
            pen=pen,
            fillLevel=0,
            fillBrush=pg.mkBrush(0, 229, 255, 20),
        )
        
        self._plot_widget.setObjectName("SparklinePlot")
        self._plot_widget.setStyleSheet(f"""
            #SparklinePlot {{
                border: 1px solid {BORDER_COLOR};
                border-radius: 12px;
                background-color: {BG_DARK};
            }}
        """)
        root.addWidget(self._plot_widget)

        # ── Bottom row ──
        bottom = QHBoxLayout()
        bottom.setSpacing(14)

        # -- Recent alerts panel --
        alerts_frame = QFrame()
        alerts_frame.setObjectName("AlertsPanel")
        alerts_frame.setStyleSheet(_PANEL_STYLE_ALERTS)
        alerts_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        alerts_vbox = QVBoxLayout(alerts_frame)
        alerts_vbox.setContentsMargins(16, 14, 16, 14)
        alerts_vbox.setSpacing(10)

        alerts_header = QLabel("📋  Recent Alerts")
        alerts_header.setStyleSheet(_HEADER_LABEL_STYLE)
        alerts_vbox.addWidget(alerts_header)

        self._alerts_list = QListWidget()
        self._alerts_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {BG_DARK};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
                font-size: 12px;
                padding: 4px;
            }}
            QListWidget::item {{
                padding: 8px 10px;
                border-bottom: 1px solid {BORDER_COLOR};
            }}
            QListWidget::item:hover {{
                background-color: rgba(255, 255, 255, 0.02);
            }}
            QListWidget::item:selected {{
                background-color: rgba(0, 229, 255, 0.1);
                color: {ACCENT_CYAN};
            }}
        """)
        self._alerts_list.setMaximumHeight(220)
        alerts_vbox.addWidget(self._alerts_list)
        bottom.addWidget(alerts_frame, stretch=3)

        # -- Quick actions panel --
        actions_frame = QFrame()
        actions_frame.setObjectName("ActionsPanel")
        actions_frame.setStyleSheet(_PANEL_STYLE_ACTIONS)
        actions_frame.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        actions_vbox = QVBoxLayout(actions_frame)
        actions_vbox.setContentsMargins(16, 14, 16, 14)
        actions_vbox.setSpacing(12)

        actions_header = QLabel("⚡  Quick Actions")
        actions_header.setStyleSheet(_HEADER_LABEL_STYLE)
        actions_vbox.addWidget(actions_header)

        btn_arp = QPushButton("🔎  Run ARP Scan")
        btn_dns = QPushButton("🌐  Start DNS Sniff")
        btn_port = QPushButton("🛡️  Quick Port Scan")

        for btn in (btn_arp, btn_dns, btn_port):
            btn.setStyleSheet(_BUTTON_STYLE)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setMinimumHeight(42)
            actions_vbox.addWidget(btn)

        btn_arp.clicked.connect(self.action_arp_scan.emit)
        btn_dns.clicked.connect(self.action_dns_sniff.emit)
        btn_port.clicked.connect(self.action_port_scan.emit)

        actions_vbox.addStretch()
        bottom.addWidget(actions_frame, stretch=2)

        root.addLayout(bottom)

    # ── Public API ───────────────────────────────────────────────────────
    def set_host_count(self, n: int):
        self._card_hosts.set_value(str(n))

    def set_packet_rate(self, r: float):
        self._card_pps.set_value(f"{r:.1f}")

    def set_alert_count(self, n: int):
        color = DANGER_RED if n > 0 else SUCCESS_GREEN
        self._card_alerts.set_value(str(n), trend_color=color)

    def set_port_count(self, n: int):
        self._card_ports.set_value(str(n))

    def update_packet_rate(self, rate: float):
        """Push a new data point onto the sparkline and refresh the graph."""
        self._packet_data.append(rate)
        x = list(range(-len(self._packet_data) + 1, 1))
        y = list(self._packet_data)
        self._sparkline_curve.setData(x, y)
        self.set_packet_rate(rate)

    def add_alert(self, alert: dict):
        """Prepend a new alert to the list.

        Expected keys: timestamp (str), type (str), description (str), severity (str).
        Severity is one of: 'critical', 'warning', 'info'.
        """
        timestamp = alert.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        alert_type = alert.get("type", "INFO")
        description = alert.get("description", "")
        severity = alert.get("severity", "info").lower()

        color_map = {
            "critical": DANGER_RED,
            "warning": WARNING_AMBER,
            "info": ACCENT_CYAN,
        }
        badge_color = color_map.get(severity, ACCENT_CYAN)

        text = f"[{timestamp}]  [{alert_type}]  {description}"
        item = QListWidgetItem(text)
        item.setForeground(QColor(badge_color))
        item.setFont(QFont("Consolas", 11))
        self._alerts_list.insertItem(0, item)

        # Keep only 10 alerts visible
        while self._alerts_list.count() > 10:
            self._alerts_list.takeItem(self._alerts_list.count() - 1)
