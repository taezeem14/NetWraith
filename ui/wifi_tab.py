"""
NetWraith — Wi-Fi Spectrum Auditor Tab
======================================
Displays detected wireless access points and visualizes signal overlap
using bell curves on a PyQtGraph channel spectrum layout.
"""

import numpy as np
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QLabel, QAbstractItemView,
    QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
import pyqtgraph as pg

# Theme Constants
BG_DARK = "#0d0f14"
BG_PANEL = "#1a1d24"
ACCENT_CYAN = "#00e5ff"
BORDER_COLOR = "#2a2d35"
TEXT_PRIMARY = "#ffffff"
TEXT_SECONDARY = "#8a8f98"
SUCCESS_GREEN = "#4caf50"
WARNING_AMBER = "#ffb74d"
PURPLE = "#bb86fc"

_COLUMNS = ["SSID", "Signal", "Channel", "Security", "BSSID"]

class WiFiTab(QWidget):
    """Auditing interface for wireless channels and overlapping APs."""

    scan_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._networks: list[dict] = []
        self._plot_curves: list = []
        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ── Top control bar ──
        bar = QHBoxLayout()
        self.btn_scan = QPushButton("📶  Scan Wi-Fi Spectrum")
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_CYAN};
                color: {BG_DARK};
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-size: 13px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #33eaff;
            }}
            QPushButton:pressed {{
                background-color: #00bcd4;
            }}
            QPushButton:disabled {{
                background-color: {BORDER_COLOR};
                color: {TEXT_SECONDARY};
            }}
        """)
        self.btn_scan.clicked.connect(self.scan_requested.emit)
        bar.addWidget(self.btn_scan)

        self.lbl_status = QLabel("Audit Ready — Run scan to capture nearby wireless signals.")
        self.lbl_status.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; padding-left: 10px;")
        bar.addWidget(self.lbl_status)
        bar.addStretch()
        root.addLayout(bar)

        # ── Main View Splitter (Left: Table | Right: Plot) ──
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                width: 3px;
            }}
        """)

        # Left table panel
        table_frame = QFrame()
        table_frame.setStyleSheet(f"border: 1px solid {BORDER_COLOR}; border-radius: 8px; background-color: {BG_PANEL};")
        tf_lay = QVBoxLayout(table_frame)
        tf_lay.setContentsMargins(8, 8, 8, 8)
        
        tbl_title = QLabel("📡  Detected Wireless Networks")
        tbl_title.setStyleSheet("color: #ffffff; font-weight: bold; border: none; font-size: 13px;")
        tf_lay.addWidget(tbl_title)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {BG_DARK};
                alternate-background-color: {BG_PANEL};
                color: {TEXT_PRIMARY};
                gridline-color: {BORDER_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
            }}
            QHeaderView::section {{
                background-color: {BG_PANEL};
                color: {ACCENT_CYAN};
                padding: 6px;
                font-weight: bold;
            }}
        """)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        tf_lay.addWidget(self.table)
        splitter.addWidget(table_frame)

        # Right Plot Panel
        plot_frame = QFrame()
        plot_frame.setStyleSheet(f"border: 1px solid {BORDER_COLOR}; border-radius: 8px; background-color: {BG_PANEL};")
        pf_lay = QVBoxLayout(plot_frame)
        pf_lay.setContentsMargins(8, 8, 8, 8)

        plt_title = QLabel("📊  Wireless Channel Overlap Spectrum")
        plt_title.setStyleSheet("color: #ffffff; font-weight: bold; border: none; font-size: 13px;")
        pf_lay.addWidget(plt_title)

        self.plot = pg.PlotWidget()
        self.plot.setBackground(BG_DARK)
        self.plot.showGrid(x=True, y=True, alpha=0.15)
        self.plot.setLabel("left", "Signal Strength (%)", color=TEXT_SECONDARY)
        self.plot.setLabel("bottom", "Channel", color=TEXT_SECONDARY)
        self.plot.setYRange(0, 100)
        self.plot.setXRange(1, 14)  # Default focus on 2.4GHz channels
        self.plot.getAxis("left").setPen(pg.mkPen(color=BORDER_COLOR))
        self.plot.getAxis("bottom").setPen(pg.mkPen(color=BORDER_COLOR))
        self.plot.getAxis("left").setTextPen(pg.mkPen(color=TEXT_SECONDARY))
        self.plot.getAxis("bottom").setTextPen(pg.mkPen(color=TEXT_SECONDARY))
        self.plot.setMouseEnabled(x=True, y=False)
        pf_lay.addWidget(self.plot)

        splitter.addWidget(plot_frame)
        splitter.setSizes([550, 650])
        root.addWidget(splitter, 1)

    def set_scanning(self, active: bool):
        self.btn_scan.setEnabled(not active)
        self.btn_scan.setText("⏳  Scanning Spectrum…" if active else "📶  Scan Wi-Fi Spectrum")
        if active:
            self.lbl_status.setText("Auditing local airwaves. Please wait...")
            self.table.setRowCount(0)
            self.plot.clear()
            self._plot_curves.clear()

    def set_networks(self, networks: list[dict]):
        self._networks = networks
        self.table.setRowCount(0)
        self.plot.clear()
        self._plot_curves.clear()

        # Group networks into 2.4GHz (1-14) vs 5GHz (15+)
        max_chan = 14
        for net in networks:
            chan = net.get("channel", 1)
            if chan > max_chan:
                max_chan = max(max_chan, chan)

        self.plot.setXRange(1, max_chan + 1)

        # Palette colors for curves
        curve_colors = [
            (0, 229, 255),  # Cyan
            (187, 134, 252),# Purple
            (76, 175, 80),  # Green
            (255, 183, 77), # Amber
            (255, 76, 76),  # Red
            (64, 196, 255)  # Light Blue
        ]

        for idx, net in enumerate(networks):
            row = self.table.rowCount()
            self.table.insertRow(row)

            def _item(text: str) -> QTableWidgetItem:
                item = QTableWidgetItem(str(text))
                item.setForeground(QColor(TEXT_PRIMARY))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                return item

            sig = net.get("signal", 50)
            chan = net.get("channel", 6)

            self.table.setItem(row, 0, _item(net.get("ssid", "Unknown")))
            self.table.setItem(row, 1, _item(f"{sig}%"))
            self.table.setItem(row, 2, _item(str(chan)))
            self.table.setItem(row, 3, _item(net.get("security", "WPA2")))
            self.table.setItem(row, 4, _item(net.get("bssid", "FF:FF:FF:FF:FF:FF")))

            # Draw overlap bell curve on plot
            # y(x) = H * exp(-((x - C)/W)^2)
            center = float(chan)
            height = float(sig)
            
            # Width of curve (2.4GHz signals span ~4 channels wide, 5GHz is narrow)
            width = 2.0 if chan <= 14 else 1.0

            x = np.linspace(center - 3.5 * width, center + 3.5 * width, 100)
            y = height * np.exp(-((x - center) / width) ** 2)

            color_rgb = curve_colors[idx % len(curve_colors)]
            pen = pg.mkPen(color=color_rgb, width=2)
            brush_color = QColor(*color_rgb)
            brush_color.setAlpha(20)  # semi-translucent

            curve = self.plot.plot(
                x, y, pen=pen, fillLevel=0,
                fillBrush=pg.mkBrush(brush_color),
                name=net.get("ssid", "Unknown")
            )
            self._plot_curves.append(curve)

        self.lbl_status.setText(f"Audit completed — {len(networks)} network access points analyzed.")
