"""
NetWraith — DHCP Tab
Rogue DHCP server detector with event table, alert log,
and dynamic legitimate-server info card.
"""

from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QSplitter, QFrame, QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont, QTextCursor

# ── Theme ────────────────────────────────────────────────────────
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

TABLE_STYLE = f"""
QTableWidget {{
    background-color: {BG_DARK};
    alternate-background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    gridline-color: {BORDER_COLOR};
    selection-background-color: rgba(0, 229, 255, 0.15);
    selection-color: {ACCENT_CYAN};
    font-size: 13px;
}}
QTableWidget::item {{
    padding: 4px 8px;
}}
QHeaderView::section {{
    background-color: {BG_PANEL};
    color: {ACCENT_CYAN};
    border: 1px solid {BORDER_COLOR};
    padding: 6px 8px;
    font-weight: bold;
    font-size: 13px;
}}
QTableWidget::item:selected {{
    background-color: rgba(0, 229, 255, 0.18);
}}
"""

BUTTON_STYLE = f"""
QPushButton {{
    background-color: {BG_PANEL};
    color: {ACCENT_CYAN};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    padding: 6px 16px;
    font-weight: bold;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: rgba(0, 229, 255, 0.12);
    border-color: {ACCENT_CYAN};
}}
QPushButton:pressed {{
    background-color: rgba(0, 229, 255, 0.22);
}}
"""

BUTTON_SUCCESS_STYLE = f"""
QPushButton {{
    background-color: {BG_PANEL};
    color: {SUCCESS_GREEN};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    padding: 6px 16px;
    font-weight: bold;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: rgba(76, 175, 80, 0.12);
    border-color: {SUCCESS_GREEN};
}}
QPushButton:pressed {{
    background-color: rgba(76, 175, 80, 0.22);
}}
"""

BUTTON_DANGER_STYLE = f"""
QPushButton {{
    background-color: {BG_PANEL};
    color: {DANGER_RED};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    padding: 6px 16px;
    font-weight: bold;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: rgba(255, 76, 76, 0.12);
    border-color: {DANGER_RED};
}}
QPushButton:pressed {{
    background-color: rgba(255, 76, 76, 0.22);
}}
"""

LOG_STYLE = f"""
QTextEdit {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    padding: 6px;
}}
"""

# ── Status badge helpers ─────────────────────────────────────────
STATUS_MAP = {
    "LEGITIMATE": (SUCCESS_GREEN, "#143a1a"),
    "ROGUE":      (DANGER_RED,    "#3a1414"),
    "UNKNOWN":    (TEXT_SECONDARY, "#2a2d35"),
}


def _status_badge(status: str) -> QLabel:
    fg, bg = STATUS_MAP.get(status.upper(), (TEXT_SECONDARY, "#2a2d35"))
    lbl = QLabel(status.upper())
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setStyleSheet(f"""
        QLabel {{
            background-color: {bg};
            color: {fg};
            border-radius: 8px;
            padding: 2px 10px;
            font-weight: bold;
            font-size: 12px;
        }}
    """)
    return lbl


def _info_card(title: str, value: str, color: str) -> QFrame:
    """Create a small info card widget."""
    card = QFrame()
    card.setStyleSheet(f"""
        QFrame {{
            background-color: {BG_PANEL};
            border: 1px solid {BORDER_COLOR};
            border-radius: 6px;
            padding: 10px;
        }}
    """)
    lay = QVBoxLayout(card)
    lay.setContentsMargins(12, 10, 12, 10)
    lay.setSpacing(4)

    t = QLabel(title)
    t.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; border: none; font-weight: bold;")
    lay.addWidget(t)

    v = QLabel(value)
    v.setObjectName("card_value")
    v.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: bold; border: none;")
    lay.addWidget(v)

    return card


class DHCPTab(QWidget):
    """Rogue DHCP server detector tab."""

    monitoring_toggled = pyqtSignal(bool)

    COLUMNS = ["Client MAC", "Offered IP", "DHCP Server", "Lease Time", "Status", "Timestamp"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._monitoring = False
        self._legitimate_server = "—"
        self._rogue_flash_on = True
        self._flash_timer = QTimer(self)
        self._flash_timer.setInterval(600)
        self._flash_timer.timeout.connect(self._flash_rogue_rows)
        self.setup_ui()

    # ── UI ───────────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ─── Info card row ───
        card_row = QHBoxLayout()
        card_row.setSpacing(10)

        self.card_server = _info_card("Legitimate DHCP Server", "—", ACCENT_CYAN)
        card_row.addWidget(self.card_server)

        self.card_events = _info_card("Events", "0", TEXT_PRIMARY)
        card_row.addWidget(self.card_events)

        self.card_rogue = _info_card("Rogue Servers Detected", "0", DANGER_RED)
        card_row.addWidget(self.card_rogue)

        root.addLayout(card_row)

        # ─── Control bar ───
        bar = QHBoxLayout()
        bar.setSpacing(6)

        self.btn_toggle = QPushButton("▶  Start DHCP Monitoring")
        self.btn_toggle.setStyleSheet(BUTTON_SUCCESS_STYLE)
        self.btn_toggle.setFixedHeight(34)
        self.btn_toggle.clicked.connect(self._on_toggle)
        bar.addWidget(self.btn_toggle)

        self.lbl_server = QLabel("Legitimate Server: —")
        self.lbl_server.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; padding-left: 12px;")
        bar.addWidget(self.lbl_server)
        bar.addStretch()

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.setStyleSheet(BUTTON_STYLE)
        self.btn_clear.setFixedHeight(34)
        self.btn_clear.clicked.connect(self.clear_table)
        bar.addWidget(self.btn_clear)

        root.addLayout(bar)

        # ─── Splitter: table + alert log ───
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                height: 3px;
            }}
        """)

        # Event table
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setStyleSheet(TABLE_STYLE)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, 130)
        splitter.addWidget(self.table)

        # Alert log
        alert_frame = QFrame()
        alert_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_COLOR};
                border-radius: 4px;
            }}
        """)
        af_lay = QVBoxLayout(alert_frame)
        af_lay.setContentsMargins(8, 8, 8, 8)
        af_lay.setSpacing(4)

        alert_title = QLabel("⚠  Alert Log")
        alert_title.setStyleSheet(f"color: {WARNING_AMBER}; font-weight: bold; font-size: 13px; border: none;")
        af_lay.addWidget(alert_title)

        self.alert_log = QTextEdit()
        self.alert_log.setReadOnly(True)
        self.alert_log.setStyleSheet(LOG_STYLE)
        af_lay.addWidget(self.alert_log)

        splitter.addWidget(alert_frame)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

    # ── Public API ───────────────────────────────────────────────
    def add_dhcp_event(self, event_dict: dict):
        """Append a DHCP event row.

        Expected keys: client_mac, offered_ip, server_ip, lease_time, status, timestamp
        """
        row = self.table.rowCount()
        self.table.insertRow(row)

        fields = ["client_mac", "offered_ip", "server_ip", "lease_time"]
        for col, key in enumerate(fields):
            item = QTableWidgetItem(str(event_dict.get(key, "")))
            self.table.setItem(row, col, item)

        # Status badge
        status = event_dict.get("status", "UNKNOWN").upper()
        badge = _status_badge(status)
        self.table.setCellWidget(row, 4, badge)

        ts = event_dict.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        self.table.setItem(row, 5, QTableWidgetItem(str(ts)))

        # Update counters
        self._update_cards()

        if status == "ROGUE" and not self._flash_timer.isActive():
            self._flash_timer.start()

        self.table.scrollToBottom()

    def add_alert(self, alert_dict: dict):
        """Append an alert to the log panel.

        Expected keys: timestamp, severity, message
        """
        ts = alert_dict.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        sev = alert_dict.get("severity", "INFO").upper()
        msg = alert_dict.get("message", "")

        sev_colors = {"CRITICAL": DANGER_RED, "WARNING": WARNING_AMBER, "INFO": ACCENT_CYAN}
        color = sev_colors.get(sev, TEXT_SECONDARY)

        html = (
            f'<span style="color:{TEXT_SECONDARY}">[{ts}]</span> '
            f'<span style="color:{color}; font-weight:bold">[{sev}]</span> '
            f'<span style="color:{TEXT_PRIMARY}">{msg}</span>'
        )
        self.alert_log.append(html)
        self.alert_log.moveCursor(QTextCursor.MoveOperation.End)

    def set_legitimate_server(self, ip: str):
        """Update the legitimate-server display."""
        self._legitimate_server = ip
        self.lbl_server.setText(f"Legitimate Server: {ip}")
        val_lbl = self.card_server.findChild(QLabel, "card_value")
        if val_lbl:
            val_lbl.setText(ip)

    def clear_table(self):
        """Remove all rows and reset counters."""
        self.table.setRowCount(0)
        self.alert_log.clear()
        self._flash_timer.stop()
        self._update_cards()

    # ── Private ──────────────────────────────────────────────────
    def _on_toggle(self):
        new_state = not self._monitoring
        self._monitoring = new_state
        if new_state:
            self.btn_toggle.setText("■  Stop Monitoring")
            self.btn_toggle.setStyleSheet(BUTTON_DANGER_STYLE)
        else:
            self.btn_toggle.setText("▶  Start DHCP Monitoring")
            self.btn_toggle.setStyleSheet(BUTTON_SUCCESS_STYLE)
            self._flash_timer.stop()
        self.monitoring_toggled.emit(new_state)

    def _update_cards(self):
        total = self.table.rowCount()
        rogue_count = 0
        for r in range(total):
            w = self.table.cellWidget(r, 4)
            if w and isinstance(w, QLabel) and w.text() == "ROGUE":
                rogue_count += 1

        ev_lbl = self.card_events.findChild(QLabel, "card_value")
        if ev_lbl:
            ev_lbl.setText(str(total))

        rg_lbl = self.card_rogue.findChild(QLabel, "card_value")
        if rg_lbl:
            rg_lbl.setText(str(rogue_count))

    def _flash_rogue_rows(self):
        """Toggle red background on ROGUE rows for attention."""
        self._rogue_flash_on = not self._rogue_flash_on
        for r in range(self.table.rowCount()):
            w = self.table.cellWidget(r, 4)
            if w and isinstance(w, QLabel) and w.text() == "ROGUE":
                if self._rogue_flash_on:
                    for c in range(self.table.columnCount()):
                        item = self.table.item(r, c)
                        if item:
                            item.setBackground(QColor("#3a1414"))
                else:
                    for c in range(self.table.columnCount()):
                        item = self.table.item(r, c)
                        if item:
                            item.setBackground(QColor(BG_DARK))
