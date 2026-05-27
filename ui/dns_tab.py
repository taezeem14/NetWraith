"""
NetWraith — DNS Tab
DNS query monitor with live sniffing, filtering, anomaly detection, and CSV export.
"""

import csv
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QTextEdit,
    QAbstractItemView, QSplitter, QFrame, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor

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
_COLUMNS = ["Timestamp", "Source IP", "Query Type", "Domain", "Response", "Latency", "Flags"]

# ── Anomaly flag colours ─────────────────────────────────────────────────────
_FLAG_COLORS = {
    "DNS_TUNNELING": DANGER_RED,
    "HIGH_QUERY_RATE": WARNING_AMBER,
}

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

_COMBO_STYLE = f"""
    QComboBox {{
        background-color: {BG_PANEL};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_COLOR};
        border-radius: 6px;
        padding: 7px 12px;
        font-size: 13px;
        min-width: 100px;
    }}
    QComboBox:hover {{
        border-color: {ACCENT_CYAN};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 24px;
    }}
    QComboBox::down-arrow {{
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid {ACCENT_CYAN};
        margin-right: 8px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {BG_PANEL};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_COLOR};
        selection-background-color: #252830;
        selection-color: {TEXT_PRIMARY};
        outline: none;
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
"""

_BTN_GREEN_STYLE = f"""
    QPushButton {{
        background-color: {SUCCESS_GREEN};
        color: {BG_DARK};
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        font-size: 13px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: #66bb6a;
    }}
    QPushButton:pressed {{
        background-color: #388e3c;
    }}
"""

_BTN_RED_STYLE = f"""
    QPushButton {{
        background-color: {DANGER_RED};
        color: {TEXT_PRIMARY};
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        font-size: 13px;
        font-weight: bold;
    }}
    QPushButton:hover {{
        background-color: #ff6b6b;
    }}
    QPushButton:pressed {{
        background-color: #e04343;
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

_ALERT_LOG_STYLE = f"""
    QTextEdit {{
        background-color: {BG_DARK};
        color: {TEXT_PRIMARY};
        border: 1px solid {BORDER_COLOR};
        border-radius: 6px;
        font-family: Consolas;
        font-size: 12px;
        padding: 8px;
    }}
"""


def _make_flag_item(flag: str) -> QTableWidgetItem:
    """Create a coloured badge table item for an anomaly flag."""
    color = _FLAG_COLORS.get(flag.upper(), TEXT_SECONDARY)
    item = QTableWidgetItem(f"  {flag}  ")
    item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
    item.setForeground(QColor(BG_DARK))
    item.setBackground(QColor(color))
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS Tab
# ═══════════════════════════════════════════════════════════════════════════════
class DNSTab(QWidget):
    """DNS query monitor tab with filtering and anomaly detection."""

    sniffing_toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._sniffing = False
        self.setup_ui()

    # ── UI Construction ──────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # ── Top toolbar ──────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self._btn_toggle = QPushButton("▶  Start DNS Sniffing")
        self._btn_toggle.setStyleSheet(_BTN_GREEN_STYLE)
        self._btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_toggle.setMinimumWidth(200)
        self._btn_toggle.clicked.connect(self._on_toggle_clicked)
        toolbar.addWidget(self._btn_toggle)

        self._btn_export = QPushButton("📁  Export CSV")
        self._btn_export.setStyleSheet(_BTN_SECONDARY_STYLE)
        self._btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_export.clicked.connect(self._export_csv)
        toolbar.addWidget(self._btn_export)

        self._btn_clear = QPushButton("🗑  Clear")
        self._btn_clear.setStyleSheet(_BTN_SECONDARY_STYLE)
        self._btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_clear.clicked.connect(self.clear_table)
        toolbar.addWidget(self._btn_clear)

        toolbar.addStretch()

        self._status_label = QLabel("⏹  Sniffing stopped")
        self._status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        toolbar.addWidget(self._status_label)

        root.addLayout(toolbar)

        # ── Filter bar ───────────────────────────────────────────────────
        filter_frame = QFrame()
        filter_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
            }}
        """)
        filter_layout = QHBoxLayout(filter_frame)
        filter_layout.setContentsMargins(12, 8, 12, 8)
        filter_layout.setSpacing(10)

        filter_icon = QLabel("🔎  Filter:")
        filter_icon.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; background: transparent; border: none;")
        filter_layout.addWidget(filter_icon)

        self._filter_domain = QLineEdit()
        self._filter_domain.setPlaceholderText("Domain keyword…")
        self._filter_domain.setStyleSheet(_INPUT_STYLE)
        self._filter_domain.setMaximumWidth(220)
        filter_layout.addWidget(self._filter_domain)

        self._filter_qtype = QComboBox()
        self._filter_qtype.addItems(["All", "A", "AAAA", "MX", "TXT", "CNAME", "NS"])
        self._filter_qtype.setStyleSheet(_COMBO_STYLE)
        filter_layout.addWidget(self._filter_qtype)

        self._filter_src_ip = QLineEdit()
        self._filter_src_ip.setPlaceholderText("Source IP…")
        self._filter_src_ip.setStyleSheet(_INPUT_STYLE)
        self._filter_src_ip.setMaximumWidth(180)
        filter_layout.addWidget(self._filter_src_ip)

        btn_apply = QPushButton("Apply Filter")
        btn_apply.setStyleSheet(_BTN_CYAN_STYLE)
        btn_apply.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_apply.clicked.connect(self.apply_filter)
        filter_layout.addWidget(btn_apply)

        filter_layout.addStretch()
        root.addWidget(filter_frame)

        # ── Splitter: table + anomaly panel ──────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                height: 3px;
            }}
        """)

        # -- DNS Table --
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(True)
        self._table.setStyleSheet(_TABLE_STYLE)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        splitter.addWidget(self._table)

        # -- Anomaly alert panel --
        anomaly_frame = QFrame()
        anomaly_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
            }}
        """)
        anomaly_layout = QVBoxLayout(anomaly_frame)
        anomaly_layout.setContentsMargins(12, 10, 12, 10)
        anomaly_layout.setSpacing(6)

        anomaly_header = QLabel("🚨  DNS Anomaly Alerts")
        anomaly_header.setStyleSheet(f"color: {DANGER_RED}; font-size: 14px; font-weight: bold; background: transparent; border: none;")
        anomaly_layout.addWidget(anomaly_header)

        self._anomaly_log = QTextEdit()
        self._anomaly_log.setReadOnly(True)
        self._anomaly_log.setStyleSheet(_ALERT_LOG_STYLE)
        self._anomaly_log.setMaximumHeight(180)
        anomaly_layout.addWidget(self._anomaly_log)

        splitter.addWidget(anomaly_frame)
        splitter.setSizes([400, 180])

        root.addWidget(splitter, stretch=1)

    # ── Toggle sniffing ──────────────────────────────────────────────────
    def _on_toggle_clicked(self):
        self._sniffing = not self._sniffing
        self._update_toggle_ui()
        self.sniffing_toggled.emit(self._sniffing)

    def _update_toggle_ui(self):
        if self._sniffing:
            self._btn_toggle.setText("⏹  Stop DNS Sniffing")
            self._btn_toggle.setStyleSheet(_BTN_RED_STYLE)
            self._status_label.setText("🟢  Sniffing active")
            self._status_label.setStyleSheet(f"color: {SUCCESS_GREEN}; font-size: 12px;")
        else:
            self._btn_toggle.setText("▶  Start DNS Sniffing")
            self._btn_toggle.setStyleSheet(_BTN_GREEN_STYLE)
            self._status_label.setText("⏹  Sniffing stopped")
            self._status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")

    # ── Public API ───────────────────────────────────────────────────────
    def add_dns_entry(self, entry_dict: dict):
        """Add a DNS query row to the table.

        Expected keys: timestamp, source_ip, query_type, domain, response, latency, flags.
        flags can be a string like 'DNS_TUNNELING', 'HIGH_QUERY_RATE', or '' for none.
        """
        row = self._table.rowCount()
        self._table.insertRow(row)

        def _item(text: str) -> QTableWidgetItem:
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(TEXT_PRIMARY))
            item.setFont(QFont("Consolas", 11))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            return item

        now_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        self._table.setItem(row, 0, _item(entry_dict.get("timestamp", now_str)))
        self._table.setItem(row, 1, _item(entry_dict.get("source_ip", "")))
        self._table.setItem(row, 2, _item(entry_dict.get("query_type", "A")))
        self._table.setItem(row, 3, _item(entry_dict.get("domain", "")))
        self._table.setItem(row, 4, _item(entry_dict.get("response", "")))
        self._table.setItem(row, 5, _item(entry_dict.get("latency", "—")))

        flag = entry_dict.get("flags", "").strip()
        if flag:
            self._table.setItem(row, 6, _make_flag_item(flag))
        else:
            clean = QTableWidgetItem("—")
            clean.setForeground(QColor(TEXT_SECONDARY))
            clean.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            clean.setFlags(clean.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._table.setItem(row, 6, clean)

        self._table.scrollToBottom()

    def add_anomaly(self, anomaly_dict: dict):
        """Append a DNS anomaly alert to the log.

        Expected keys: timestamp, type, message, severity.
        """
        timestamp = anomaly_dict.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        anomaly_type = anomaly_dict.get("type", "UNKNOWN")
        message = anomaly_dict.get("message", "")
        severity = anomaly_dict.get("severity", "warning").lower()

        color_map = {
            "critical": DANGER_RED,
            "warning": WARNING_AMBER,
            "info": ACCENT_CYAN,
        }
        color = color_map.get(severity, WARNING_AMBER)

        cursor = self._anomaly_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor(TEXT_SECONDARY))
        ts_fmt.setFontFamily("Consolas")
        cursor.insertText(f"[{timestamp}] ", ts_fmt)

        type_fmt = QTextCharFormat()
        type_fmt.setForeground(QColor(color))
        type_fmt.setFontWeight(QFont.Weight.Bold)
        type_fmt.setFontFamily("Consolas")
        cursor.insertText(f"[{anomaly_type}] ", type_fmt)

        msg_fmt = QTextCharFormat()
        msg_fmt.setForeground(QColor(TEXT_PRIMARY))
        msg_fmt.setFontFamily("Consolas")
        cursor.insertText(f"{message}\n", msg_fmt)

        self._anomaly_log.setTextCursor(cursor)
        self._anomaly_log.ensureCursorVisible()

    def clear_table(self):
        self._table.setRowCount(0)

    def apply_filter(self):
        """Hide rows that don't match the current filter criteria."""
        domain_kw = self._filter_domain.text().strip().lower()
        qtype_filter = self._filter_qtype.currentText()
        src_ip_filter = self._filter_src_ip.text().strip()

        for row in range(self._table.rowCount()):
            visible = True

            # Domain keyword filter
            if domain_kw:
                domain_item = self._table.item(row, 3)
                if domain_item and domain_kw not in domain_item.text().lower():
                    visible = False

            # Query type filter
            if visible and qtype_filter != "All":
                qtype_item = self._table.item(row, 2)
                if qtype_item and qtype_item.text().strip().upper() != qtype_filter.upper():
                    visible = False

            # Source IP filter
            if visible and src_ip_filter:
                src_item = self._table.item(row, 1)
                if src_item and src_ip_filter not in src_item.text():
                    visible = False

            self._table.setRowHidden(row, not visible)

    # ── CSV Export ───────────────────────────────────────────────────────
    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export DNS Log to CSV", "dns_export.csv", "CSV Files (*.csv)"
        )
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(_COLUMNS)
            for row in range(self._table.rowCount()):
                if self._table.isRowHidden(row):
                    continue
                row_data = []
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    row_data.append(item.text().strip() if item else "")
                writer.writerow(row_data)

        self._status_label.setText(f"Exported to {path}")
