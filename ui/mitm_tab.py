"""
NetWraith — MITM Tab
Man-in-the-Middle attack detection with info cards, detection-status
table, threat log, and real-time event log.
"""

from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QSplitter, QFrame, QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal
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

# ── Threat level colours ─────────────────────────────────────────
THREAT_LEVELS = {
    "SAFE":     (SUCCESS_GREEN, "#143a1a"),
    "WARNING":  (WARNING_AMBER, "#3a2e14"),
    "CRITICAL": (DANGER_RED,    "#3a1414"),
}

# Check status colours
CHECK_STATUS = {
    "PASS":    (SUCCESS_GREEN, "#143a1a"),
    "FAIL":    (DANGER_RED,    "#3a1414"),
    "PENDING": (TEXT_SECONDARY, "#2a2d35"),
}

# Severity colours for threat table
SEVERITY_COLORS = {
    "CRITICAL": (DANGER_RED,    "#3a1414"),
    "WARNING":  (WARNING_AMBER, "#3a2e14"),
    "INFO":     (ACCENT_CYAN,   "#0a2a30"),
}

# Default check rows
DEFAULT_CHECKS = [
    "Gateway MAC Check",
    "Duplicate IP Check",
    "ICMP Redirect Monitor",
    "TTL Anomaly Check",
    "ARP Consistency Check",
]


def _badge_label(text: str, fg: str, bg: str) -> QLabel:
    lbl = QLabel(text)
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


def _info_card(title: str, value: str, accent: str, obj_name: str = "") -> QFrame:
    card = QFrame()
    if obj_name:
        card.setObjectName(obj_name)
    card.setStyleSheet(f"""
        QFrame#{obj_name if obj_name else ''} {{
            background-color: {BG_PANEL};
            border: 1px solid {BORDER_COLOR};
            border-radius: 8px;
        }}
    """ if obj_name else f"""
        QFrame {{
            background-color: {BG_PANEL};
            border: 1px solid {BORDER_COLOR};
            border-radius: 8px;
        }}
    """)
    lay = QVBoxLayout(card)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(6)

    t = QLabel(title)
    t.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; font-weight: bold; border: none;")
    lay.addWidget(t)

    v = QLabel(value)
    v.setObjectName("card_value")
    v.setStyleSheet(f"color: {accent}; font-size: 18px; font-weight: bold; border: none;")
    lay.addWidget(v)

    sub = QLabel("")
    sub.setObjectName("card_sub")
    sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 11px; border: none;")
    lay.addWidget(sub)

    return card


class MITMTab(QWidget):
    """Man-in-the-Middle detection tab."""

    detection_toggled = pyqtSignal(bool)

    CHECK_COLS = ["Check Type", "Last Result", "Last Checked", "Status"]
    THREAT_COLS = ["Timestamp", "Alert Type", "Severity", "Description", "Details"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._detecting = False
        self._check_count = 0
        self._current_level = "SAFE"
        self.setup_ui()
        self._init_check_rows()

    # ── UI ───────────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ─── Info cards ───
        cards = QHBoxLayout()
        cards.setSpacing(10)

        self.card_gateway = _info_card("Gateway Status", "—", ACCENT_CYAN, "card_gw")
        cards.addWidget(self.card_gateway)

        self.card_engine = _info_card("Detection Engine", "Stopped", TEXT_SECONDARY, "card_eng")
        cards.addWidget(self.card_engine)

        self.card_threat = _info_card("Threat Level", "SAFE", SUCCESS_GREEN, "card_threat")
        cards.addWidget(self.card_threat)

        root.addLayout(cards)

        # ─── Control bar ───
        bar = QHBoxLayout()
        bar.setSpacing(6)

        self.btn_toggle = QPushButton("▶  Start MITM Detection")
        self.btn_toggle.setStyleSheet(BUTTON_SUCCESS_STYLE)
        self.btn_toggle.setFixedHeight(34)
        self.btn_toggle.clicked.connect(self._on_toggle)
        bar.addWidget(self.btn_toggle)

        self.lbl_gw_ip = QLabel("Gateway IP: —")
        self.lbl_gw_ip.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; padding-left: 12px;")
        bar.addWidget(self.lbl_gw_ip)

        self.lbl_gw_mac = QLabel("MAC: —")
        self.lbl_gw_mac.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; padding-left: 8px;")
        bar.addWidget(self.lbl_gw_mac)
        bar.addStretch()

        root.addLayout(bar)

        # ─── Horizontal splitter: check table (left) + threat table (right) ───
        h_splitter = QSplitter(Qt.Orientation.Horizontal)
        h_splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                width: 3px;
            }}
        """)

        # Left – Detection status
        left_frame = QFrame()
        left_frame.setStyleSheet(f"QFrame {{ background-color: {BG_DARK}; border: none; }}")
        left_lay = QVBoxLayout(left_frame)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(4)

        lbl_checks = QLabel("Detection Checks")
        lbl_checks.setStyleSheet(f"color: {ACCENT_CYAN}; font-weight: bold; font-size: 13px;")
        left_lay.addWidget(lbl_checks)

        self.check_table = QTableWidget(0, len(self.CHECK_COLS))
        self.check_table.setHorizontalHeaderLabels(self.CHECK_COLS)
        self.check_table.setAlternatingRowColors(True)
        self.check_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.check_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.check_table.verticalHeader().setVisible(False)
        self.check_table.setStyleSheet(TABLE_STYLE)
        self.check_table.horizontalHeader().setStretchLastSection(True)
        self.check_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.check_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.check_table.setColumnWidth(3, 110)
        left_lay.addWidget(self.check_table)

        h_splitter.addWidget(left_frame)

        # Right – Threat log table
        right_frame = QFrame()
        right_frame.setStyleSheet(f"QFrame {{ background-color: {BG_DARK}; border: none; }}")
        right_lay = QVBoxLayout(right_frame)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(4)

        lbl_threats = QLabel("Threat Log")
        lbl_threats.setStyleSheet(f"color: {WARNING_AMBER}; font-weight: bold; font-size: 13px;")
        right_lay.addWidget(lbl_threats)

        self.threat_table = QTableWidget(0, len(self.THREAT_COLS))
        self.threat_table.setHorizontalHeaderLabels(self.THREAT_COLS)
        self.threat_table.setAlternatingRowColors(True)
        self.threat_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.threat_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.threat_table.verticalHeader().setVisible(False)
        self.threat_table.setStyleSheet(TABLE_STYLE)
        self.threat_table.horizontalHeader().setStretchLastSection(True)
        self.threat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.threat_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.threat_table.setColumnWidth(2, 110)
        right_lay.addWidget(self.threat_table)

        h_splitter.addWidget(right_frame)
        h_splitter.setStretchFactor(0, 2)
        h_splitter.setStretchFactor(1, 3)
        root.addWidget(h_splitter, 1)

        # ─── Bottom event log ───
        log_frame = QFrame()
        log_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_COLOR};
                border-radius: 4px;
            }}
        """)
        lf_lay = QVBoxLayout(log_frame)
        lf_lay.setContentsMargins(8, 6, 8, 6)
        lf_lay.setSpacing(4)

        log_title = QLabel("📋  Real-Time Event Log")
        log_title.setStyleSheet(f"color: {TEXT_SECONDARY}; font-weight: bold; font-size: 12px; border: none;")
        lf_lay.addWidget(log_title)

        self.event_log = QTextEdit()
        self.event_log.setReadOnly(True)
        self.event_log.setStyleSheet(LOG_STYLE)
        self.event_log.setMaximumHeight(140)
        lf_lay.addWidget(self.event_log)

        root.addWidget(log_frame)

    # ── Public API ───────────────────────────────────────────────
    def update_check_status(self, check_dict: dict):
        """Update a detection-check row.

        Expected keys: check_type, result, last_checked, status (PASS/FAIL/PENDING)
        """
        check_type = check_dict.get("check_type", "")
        # Find the matching row
        for row in range(self.check_table.rowCount()):
            item = self.check_table.item(row, 0)
            if item and item.text() == check_type:
                self.check_table.setItem(row, 1, QTableWidgetItem(str(check_dict.get("result", ""))))
                self.check_table.setItem(row, 2, QTableWidgetItem(str(check_dict.get("last_checked", ""))))
                status = check_dict.get("status", "PENDING").upper()
                fg, bg = CHECK_STATUS.get(status, (TEXT_SECONDARY, "#2a2d35"))
                badge = _badge_label(status, fg, bg)
                self.check_table.setCellWidget(row, 3, badge)
                break

        self._check_count += 1
        # Update engine card
        val = self.card_engine.findChild(QLabel, "card_value")
        if val:
            val.setText("Running" if self._detecting else "Stopped")
            val.setStyleSheet(f"color: {SUCCESS_GREEN if self._detecting else TEXT_SECONDARY}; font-size: 18px; font-weight: bold; border: none;")
        sub = self.card_engine.findChild(QLabel, "card_sub")
        if sub:
            sub.setText(f"{self._check_count} checks performed")

    def add_threat(self, threat_dict: dict):
        """Append a threat to the threat log table.

        Expected keys: timestamp, alert_type, severity, description, details
        """
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)

        ts = threat_dict.get("timestamp", datetime.now().strftime("%H:%M:%S"))
        self.threat_table.setItem(row, 0, QTableWidgetItem(str(ts)))
        self.threat_table.setItem(row, 1, QTableWidgetItem(str(threat_dict.get("alert_type", ""))))

        # Severity badge
        sev = threat_dict.get("severity", "INFO").upper()
        fg, bg = SEVERITY_COLORS.get(sev, (TEXT_SECONDARY, "#2a2d35"))
        badge = _badge_label(sev, fg, bg)
        self.threat_table.setCellWidget(row, 2, badge)

        self.threat_table.setItem(row, 3, QTableWidgetItem(str(threat_dict.get("description", ""))))
        self.threat_table.setItem(row, 4, QTableWidgetItem(str(threat_dict.get("details", ""))))
        self.threat_table.scrollToBottom()

    def set_gateway_info(self, ip: str, mac: str):
        """Update gateway IP and MAC displays."""
        self.lbl_gw_ip.setText(f"Gateway IP: {ip}")
        self.lbl_gw_mac.setText(f"MAC: {mac}")
        val = self.card_gateway.findChild(QLabel, "card_value")
        if val:
            val.setText(ip)
        sub = self.card_gateway.findChild(QLabel, "card_sub")
        if sub:
            sub.setText(mac)

    def set_threat_level(self, level: str):
        """Update the threat-level card.  Accepts 'SAFE', 'WARNING', or 'CRITICAL'."""
        self._current_level = level.upper()
        fg, bg = THREAT_LEVELS.get(self._current_level, (TEXT_SECONDARY, "#2a2d35"))
        val = self.card_threat.findChild(QLabel, "card_value")
        if val:
            val.setText(self._current_level)
            val.setStyleSheet(f"color: {fg}; font-size: 18px; font-weight: bold; border: none;")

        # Tint card border based on level
        self.card_threat.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 2px solid {fg};
                border-radius: 8px;
            }}
        """)

    def add_log_entry(self, text: str):
        """Append a timestamped entry to the event log."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        html = (
            f'<span style="color:{TEXT_SECONDARY}">[{ts}]</span> '
            f'<span style="color:{TEXT_PRIMARY}">{text}</span>'
        )
        self.event_log.append(html)
        self.event_log.moveCursor(QTextCursor.MoveOperation.End)

    # ── Private ──────────────────────────────────────────────────
    def _init_check_rows(self):
        """Pre-populate the check table with default rows."""
        for name in DEFAULT_CHECKS:
            row = self.check_table.rowCount()
            self.check_table.insertRow(row)
            item = QTableWidgetItem(name)
            font = item.font()
            font.setBold(True)
            item.setFont(font)
            self.check_table.setItem(row, 0, item)
            self.check_table.setItem(row, 1, QTableWidgetItem("—"))
            self.check_table.setItem(row, 2, QTableWidgetItem("—"))
            fg, bg = CHECK_STATUS["PENDING"]
            badge = _badge_label("PENDING", fg, bg)
            self.check_table.setCellWidget(row, 3, badge)

    def _on_toggle(self):
        new_state = not self._detecting
        self._detecting = new_state
        if new_state:
            self.btn_toggle.setText("■  Stop Detection")
            self.btn_toggle.setStyleSheet(BUTTON_DANGER_STYLE)
            self.add_log_entry("MITM detection engine started")
        else:
            self.btn_toggle.setText("▶  Start MITM Detection")
            self.btn_toggle.setStyleSheet(BUTTON_SUCCESS_STYLE)
            self.add_log_entry("MITM detection engine stopped")

        # Update engine card
        val = self.card_engine.findChild(QLabel, "card_value")
        if val:
            val.setText("Running" if new_state else "Stopped")
            val.setStyleSheet(f"color: {SUCCESS_GREEN if new_state else TEXT_SECONDARY}; font-size: 18px; font-weight: bold; border: none;")

        self.detection_toggled.emit(new_state)
