"""
NetWraith — ARP Tab
ARP spoof detection monitor with baseline management, live table, and alert log.
"""

from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QAbstractItemView, QSplitter, QFrame
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
_COLUMNS = ["IP Address", "Expected MAC", "Detected MAC", "Status", "Timestamp"]

# ── Status colour map ────────────────────────────────────────────────────────
_STATUS_COLORS = {
    "NORMAL": SUCCESS_GREEN,
    "SPOOF_DETECTED": DANGER_RED,
    "GRATUITOUS": WARNING_AMBER,
    "UNKNOWN": TEXT_SECONDARY,
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
#  ARP Tab
# ═══════════════════════════════════════════════════════════════════════════════
class ARPTab(QWidget):
    """ARP spoof detection monitor tab."""

    monitoring_toggled = pyqtSignal(bool)
    baseline_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._monitoring = False
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

        self._btn_toggle = QPushButton("▶  Start ARP Monitoring")
        self._btn_toggle.setStyleSheet(_BTN_GREEN_STYLE)
        self._btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_toggle.setMinimumWidth(220)
        self._btn_toggle.clicked.connect(self._on_toggle_clicked)
        toolbar.addWidget(self._btn_toggle)

        self._btn_baseline = QPushButton("📸  Snapshot Baseline")
        self._btn_baseline.setStyleSheet(_BTN_SECONDARY_STYLE)
        self._btn_baseline.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_baseline.clicked.connect(self.baseline_requested.emit)
        toolbar.addWidget(self._btn_baseline)

        toolbar.addStretch()

        self._status_label = QLabel("⏹  Monitoring stopped")
        self._status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        toolbar.addWidget(self._status_label)

        root.addLayout(toolbar)

        # ── Splitter: table + alert log ──────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                height: 3px;
            }}
        """)

        # -- ARP Table --
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(True)
        self._table.setStyleSheet(_TABLE_STYLE)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)

        splitter.addWidget(self._table)

        # -- Alert log panel --
        alert_panel = QFrame()
        alert_panel.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
            }}
        """)
        alert_layout = QVBoxLayout(alert_panel)
        alert_layout.setContentsMargins(12, 10, 12, 10)
        alert_layout.setSpacing(6)

        alert_header = QLabel("🔔  ARP Alert Log")
        alert_header.setStyleSheet(f"color: {ACCENT_CYAN}; font-size: 14px; font-weight: bold; background: transparent; border: none;")
        alert_layout.addWidget(alert_header)

        self._alert_log = QTextEdit()
        self._alert_log.setReadOnly(True)
        self._alert_log.setStyleSheet(_ALERT_LOG_STYLE)
        self._alert_log.setMaximumHeight(200)
        alert_layout.addWidget(self._alert_log)

        splitter.addWidget(alert_panel)
        splitter.setSizes([400, 200])

        root.addWidget(splitter, stretch=1)

    # ── Toggle monitoring ────────────────────────────────────────────────
    def _on_toggle_clicked(self):
        self._monitoring = not self._monitoring
        self.set_monitoring(self._monitoring)
        self.monitoring_toggled.emit(self._monitoring)

    # ── Public API ───────────────────────────────────────────────────────
    def set_monitoring(self, active: bool):
        """Update UI to reflect monitoring state."""
        self._monitoring = active
        if active:
            self._btn_toggle.setText("⏹  Stop ARP Monitoring")
            self._btn_toggle.setStyleSheet(_BTN_RED_STYLE)
            self._status_label.setText("🟢  Monitoring active")
            self._status_label.setStyleSheet(f"color: {SUCCESS_GREEN}; font-size: 12px;")
        else:
            self._btn_toggle.setText("▶  Start ARP Monitoring")
            self._btn_toggle.setStyleSheet(_BTN_GREEN_STYLE)
            self._status_label.setText("⏹  Monitoring stopped")
            self._status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")

    def add_arp_entry(self, entry_dict: dict):
        """Add an ARP entry row.

        Expected keys: ip, expected_mac, detected_mac, status, timestamp.
        """
        row = self._table.rowCount()
        self._table.insertRow(row)

        def _item(text: str) -> QTableWidgetItem:
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(TEXT_PRIMARY))
            item.setFont(QFont("Consolas", 11))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            return item

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._table.setItem(row, 0, _item(entry_dict.get("ip", "")))
        self._table.setItem(row, 1, _item(entry_dict.get("expected_mac", "—")))
        self._table.setItem(row, 2, _item(entry_dict.get("detected_mac", "")))

        status = entry_dict.get("status", "UNKNOWN")
        self._table.setItem(row, 3, _make_status_item(status))

        self._table.setItem(row, 4, _item(entry_dict.get("timestamp", now_str)))

        # Auto-scroll to latest
        self._table.scrollToBottom()

    def add_alert(self, alert_dict: dict):
        """Append an ARP alert to the log.

        Expected keys: timestamp, severity, message.
        severity: 'critical', 'warning', 'info'.
        """
        timestamp = alert_dict.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        severity = alert_dict.get("severity", "info").lower()
        message = alert_dict.get("message", "")

        color_map = {
            "critical": DANGER_RED,
            "warning": WARNING_AMBER,
            "info": ACCENT_CYAN,
        }
        color = color_map.get(severity, ACCENT_CYAN)

        cursor = self._alert_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Timestamp
        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor(TEXT_SECONDARY))
        ts_fmt.setFontFamily("Consolas")
        cursor.insertText(f"[{timestamp}] ", ts_fmt)

        # Severity badge
        sev_fmt = QTextCharFormat()
        sev_fmt.setForeground(QColor(color))
        sev_fmt.setFontWeight(QFont.Weight.Bold)
        sev_fmt.setFontFamily("Consolas")
        cursor.insertText(f"[{severity.upper()}] ", sev_fmt)

        # Message
        msg_fmt = QTextCharFormat()
        msg_fmt.setForeground(QColor(TEXT_PRIMARY))
        msg_fmt.setFontFamily("Consolas")
        cursor.insertText(f"{message}\n", msg_fmt)

        self._alert_log.setTextCursor(cursor)
        self._alert_log.ensureCursorVisible()

    def clear_table(self):
        self._table.setRowCount(0)
