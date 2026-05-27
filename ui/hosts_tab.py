"""
NetWraith — Hosts Tab
Host discovery via ARP scan with table display, status badges, context menu, and CSV export.
"""

import csv
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMenu, QFileDialog,
    QAbstractItemView, QProgressBar, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QAction

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

# ── Column definitions ───────────────────────────────────────────────────────
_COLUMNS = ["#", "IP Address", "MAC Address", "Vendor", "Hostname", "Status", "First Seen", "Last Seen"]

# ── Shared styles ────────────────────────────────────────────────────────────
_TABLE_STYLE = f"""
    QTableWidget {{
        background-color: {BG_DARK};
        alternate-background-color: {BG_PANEL};
        color: {TEXT_PRIMARY};
        gridline-color: {BORDER_COLOR};
        border: 1px solid {BORDER_COLOR};
        border-radius: 6px;
        font-size: 12px;
        selection-background-color: #1a3a4a;
        selection-color: {TEXT_PRIMARY};
    }}
    QTableWidget::item {{
        padding: 4px 8px;
    }}
    QHeaderView::section {{
        background-color: {BG_PANEL};
        color: {ACCENT_CYAN};
        border: 1px solid {BORDER_COLOR};
        padding: 6px 10px;
        font-weight: bold;
        font-size: 12px;
    }}
    QTableCornerButton::section {{
        background-color: {BG_PANEL};
        border: 1px solid {BORDER_COLOR};
    }}
"""

_INPUT_STYLE = f"""
    QLineEdit {{
        background-color: {BG_PANEL};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_COLOR};
        border-radius: 6px;
        padding: 8px 12px;
        font-size: 13px;
    }}
    QLineEdit:focus {{
        border-color: {ACCENT_CYAN};
    }}
"""

_BTN_CYAN_STYLE = f"""
    QPushButton {{
        background-color: {ACCENT_CYAN};
        color: {BG_DARK};
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
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
"""

_BTN_SECONDARY_STYLE = f"""
    QPushButton {{
        background-color: {BG_PANEL};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_COLOR};
        border-radius: 6px;
        padding: 8px 18px;
        font-size: 13px;
    }}
    QPushButton:hover {{
        background-color: #252830;
        border-color: {ACCENT_CYAN};
    }}
    QPushButton:pressed {{
        background-color: #2e313a;
    }}
"""

_PROGRESS_STYLE = f"""
    QProgressBar {{
        background-color: {BG_PANEL};
        border: 1px solid {BORDER_COLOR};
        border-radius: 4px;
        text-align: center;
        color: {TEXT_PRIMARY};
        font-size: 11px;
        height: 18px;
    }}
    QProgressBar::chunk {{
        background-color: {ACCENT_CYAN};
        border-radius: 3px;
    }}
"""


# ── Status badge helper ─────────────────────────────────────────────────────
_STATUS_COLORS = {
    "TRUSTED": SUCCESS_GREEN,
    "NEW": ACCENT_CYAN,
    "CHANGED": WARNING_AMBER,
    "SUSPICIOUS": DANGER_RED,
}


def _make_status_item(status: str) -> QTableWidgetItem:
    color = _STATUS_COLORS.get(status.upper(), TEXT_SECONDARY)
    item = QTableWidgetItem(f"  {status.upper()}  ")
    item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
    item.setForeground(QColor(BG_DARK))
    item.setBackground(QColor(color))
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


# ═══════════════════════════════════════════════════════════════════════════════
#  Hosts Tab
# ═══════════════════════════════════════════════════════════════════════════════
class HostsTab(QWidget):
    """Host discovery tab with ARP scan, table display, and CSV export."""

    scan_requested = pyqtSignal(str)       # ip_range
    port_scan_requested = pyqtSignal(str)  # target_ip

    def __init__(self, parent=None):
        super().__init__(parent)
        self._row_counter = 0
        self.setup_ui()

    # ── UI Construction ──────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ── Top toolbar ──────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("192.168.1.0/24")
        self._ip_input.setMinimumWidth(220)
        self._ip_input.setStyleSheet(_INPUT_STYLE)
        toolbar.addWidget(self._ip_input)

        self._btn_scan = QPushButton("🔎  Scan")
        self._btn_scan.setStyleSheet(_BTN_CYAN_STYLE)
        self._btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_scan.clicked.connect(self._on_scan_clicked)
        toolbar.addWidget(self._btn_scan)

        self._btn_export = QPushButton("📁  Export CSV")
        self._btn_export.setStyleSheet(_BTN_SECONDARY_STYLE)
        self._btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_export.clicked.connect(self._export_csv)
        toolbar.addWidget(self._btn_export)

        self._btn_clear = QPushButton("🗑  Clear")
        self._btn_clear.setStyleSheet(_BTN_SECONDARY_STYLE)
        self._btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_clear.clicked.connect(self.clear_hosts)
        toolbar.addWidget(self._btn_clear)

        toolbar.addStretch()
        root.addLayout(toolbar)

        # ── Table ────────────────────────────────────────────────────────
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(True)
        self._table.setStyleSheet(_TABLE_STYLE)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)

        root.addWidget(self._table, stretch=1)

        # ── Status bar ───────────────────────────────────────────────────
        status_row = QHBoxLayout()
        status_row.setSpacing(10)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        status_row.addWidget(self._status_label)

        self._progress = QProgressBar()
        self._progress.setStyleSheet(_PROGRESS_STYLE)
        self._progress.setMaximumWidth(260)
        self._progress.setValue(0)
        self._progress.setVisible(False)
        status_row.addWidget(self._progress)

        status_row.addStretch()

        self._host_count_label = QLabel("Hosts: 0")
        self._host_count_label.setStyleSheet(f"color: {ACCENT_CYAN}; font-size: 12px; font-weight: bold;")
        status_row.addWidget(self._host_count_label)

        root.addLayout(status_row)

    # ── Slot: scan button ────────────────────────────────────────────────
    def _on_scan_clicked(self):
        ip_range = self._ip_input.text().strip()
        if ip_range:
            self.scan_requested.emit(ip_range)

    # ── Public API ───────────────────────────────────────────────────────
    def add_host(self, host_dict: dict):
        """Add a host row to the table.

        Expected keys: ip, mac, vendor, hostname, status, first_seen, last_seen.
        """
        self._row_counter += 1
        row = self._table.rowCount()
        self._table.insertRow(row)

        def _item(text: str) -> QTableWidgetItem:
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(TEXT_PRIMARY))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            return item

        self._table.setItem(row, 0, _item(str(self._row_counter)))
        self._table.setItem(row, 1, _item(host_dict.get("ip", "")))
        self._table.setItem(row, 2, _item(host_dict.get("mac", "")))
        self._table.setItem(row, 3, _item(host_dict.get("vendor", "Unknown")))
        self._table.setItem(row, 4, _item(host_dict.get("hostname", "")))

        status = host_dict.get("status", "NEW")
        self._table.setItem(row, 5, _make_status_item(status))

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._table.setItem(row, 6, _item(host_dict.get("first_seen", now_str)))
        self._table.setItem(row, 7, _item(host_dict.get("last_seen", now_str)))

        self._host_count_label.setText(f"Hosts: {self._table.rowCount()}")

    def clear_hosts(self):
        self._table.setRowCount(0)
        self._row_counter = 0
        self._host_count_label.setText("Hosts: 0")
        self._status_label.setText("Cleared")

    def set_scanning(self, scanning: bool):
        """Toggle the scan button state and show/hide progress."""
        self._btn_scan.setEnabled(not scanning)
        self._btn_scan.setText("⏳  Scanning…" if scanning else "🔎  Scan")
        self._progress.setVisible(scanning)
        if scanning:
            self._progress.setRange(0, 0)  # indeterminate
            self._status_label.setText("Scanning network…")
        else:
            self._progress.setRange(0, 100)
            self._progress.setValue(100)
            self._status_label.setText(f"Scan complete — {self._table.rowCount()} host(s) found")

    # ── Context menu ─────────────────────────────────────────────────────
    def _show_context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {BG_PANEL};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                padding: 4px;
            }}
            QMenu::item {{
                padding: 8px 24px;
            }}
            QMenu::item:selected {{
                background-color: #252830;
            }}
        """)

        act_trusted = QAction("✅  Mark as Trusted", self)
        act_ports = QAction("🔍  Scan Ports", self)
        act_copy_mac = QAction("📋  Copy MAC", self)
        act_copy_ip = QAction("📋  Copy IP", self)

        act_trusted.triggered.connect(lambda: self._mark_trusted(row))
        act_ports.triggered.connect(lambda: self._scan_ports(row))
        act_copy_mac.triggered.connect(lambda: self._copy_cell(row, 2))
        act_copy_ip.triggered.connect(lambda: self._copy_cell(row, 1))

        menu.addAction(act_trusted)
        menu.addAction(act_ports)
        menu.addSeparator()
        menu.addAction(act_copy_mac)
        menu.addAction(act_copy_ip)
        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _mark_trusted(self, row: int):
        self._table.setItem(row, 5, _make_status_item("TRUSTED"))

    def _scan_ports(self, row: int):
        ip_item = self._table.item(row, 1)
        if ip_item:
            self.port_scan_requested.emit(ip_item.text())

    def _copy_cell(self, row: int, col: int):
        item = self._table.item(row, col)
        if item:
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(item.text().strip())

    # ── CSV Export ───────────────────────────────────────────────────────
    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Hosts to CSV", "hosts_export.csv", "CSV Files (*.csv)"
        )
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(_COLUMNS)
            for row in range(self._table.rowCount()):
                row_data = []
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    row_data.append(item.text().strip() if item else "")
                writer.writerow(row_data)

        self._status_label.setText(f"Exported {self._table.rowCount()} hosts to {path}")
