"""
NetWraith — Logs Tab
Unified alert log with module/severity/time-range filtering,
multi-format export (CSV, JSON, TXT), and persistent save/load.
"""

import csv
import json
import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QDateTimeEdit, QFileDialog, QMessageBox, QAbstractItemView,
)
from PyQt6.QtCore import Qt, QDateTime
from PyQt6.QtGui import QColor, QFont

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
QPushButton:disabled {{
    color: {TEXT_SECONDARY};
    border-color: {BORDER_COLOR};
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

COMBO_STYLE = f"""
QComboBox {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    padding: 5px 10px;
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
    selection-background-color: rgba(0, 229, 255, 0.18);
    selection-color: {ACCENT_CYAN};
    outline: none;
}}
"""

DATETIME_STYLE = f"""
QDateTimeEdit {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    padding: 5px 10px;
    font-size: 13px;
}}
QDateTimeEdit:focus {{
    border-color: {ACCENT_CYAN};
}}
QDateTimeEdit::up-button, QDateTimeEdit::down-button {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER_COLOR};
    width: 16px;
}}
QDateTimeEdit::up-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid {ACCENT_CYAN};
}}
QDateTimeEdit::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {ACCENT_CYAN};
}}
"""

# ── Module colour map ────────────────────────────────────────────
MODULE_COLORS = {
    "Hosts":   ACCENT_CYAN,
    "ARP":     SUCCESS_GREEN,
    "DNS":     PURPLE,
    "Packets": "#4fc3f7",
    "Ports":   WARNING_AMBER,
    "DHCP":    "#f48fb1",   # pink
    "SSL":     "#4db6ac",   # teal
    "MITM":    DANGER_RED,
}

SEVERITY_CONFIG = {
    "CRITICAL": (DANGER_RED,    "#3a1414"),
    "WARNING":  (WARNING_AMBER, "#3a2e14"),
    "INFO":     (ACCENT_CYAN,   "#0a2a30"),
}


def _module_badge(module: str) -> QLabel:
    color = MODULE_COLORS.get(module, TEXT_SECONDARY)
    lbl = QLabel(module)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setStyleSheet(f"""
        QLabel {{
            color: {color};
            background-color: rgba({_hex_to_rgb_str(color)}, 0.12);
            border-radius: 8px;
            padding: 2px 10px;
            font-weight: bold;
            font-size: 12px;
        }}
    """)
    return lbl


def _severity_badge(severity: str) -> QLabel:
    fg, bg = SEVERITY_CONFIG.get(severity.upper(), (TEXT_SECONDARY, "#2a2d35"))
    lbl = QLabel(severity.upper())
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


def _hex_to_rgb_str(hex_color: str) -> str:
    """Convert '#rrggbb' to 'r, g, b' for use in rgba()."""
    h = hex_color.lstrip("#")
    return f"{int(h[0:2], 16)}, {int(h[2:4], 16)}, {int(h[4:6], 16)}"


class LogsTab(QWidget):
    """Unified alert / log tab with filtering and export."""

    COLUMNS = ["Timestamp", "Module", "Severity", "Description", "Source IP", "Details"]
    MODULES = ["All", "Hosts", "ARP", "DNS", "Packets", "Ports", "DHCP", "SSL", "MITM"]
    SEVERITIES = ["All", "CRITICAL", "WARNING", "INFO"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: list[dict] = []
        self.setup_ui()

    # ── UI ───────────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ─── Filter bar ───
        fbar = QHBoxLayout()
        fbar.setSpacing(6)

        lbl_mod = QLabel("Module:")
        lbl_mod.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        fbar.addWidget(lbl_mod)

        self.combo_module = QComboBox()
        self.combo_module.addItems(self.MODULES)
        self.combo_module.setStyleSheet(COMBO_STYLE)
        self.combo_module.setFixedHeight(34)
        fbar.addWidget(self.combo_module)

        lbl_sev = QLabel("Severity:")
        lbl_sev.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        fbar.addWidget(lbl_sev)

        self.combo_severity = QComboBox()
        self.combo_severity.addItems(self.SEVERITIES)
        self.combo_severity.setStyleSheet(COMBO_STYLE)
        self.combo_severity.setFixedHeight(34)
        fbar.addWidget(self.combo_severity)

        lbl_from = QLabel("From:")
        lbl_from.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        fbar.addWidget(lbl_from)

        self.dt_from = QDateTimeEdit()
        self.dt_from.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.dt_from.setDateTime(QDateTime.currentDateTime().addDays(-1))
        self.dt_from.setStyleSheet(DATETIME_STYLE)
        self.dt_from.setFixedHeight(34)
        self.dt_from.setCalendarPopup(True)
        fbar.addWidget(self.dt_from)

        lbl_to = QLabel("To:")
        lbl_to.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        fbar.addWidget(lbl_to)

        self.dt_to = QDateTimeEdit()
        self.dt_to.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.dt_to.setDateTime(QDateTime.currentDateTime())
        self.dt_to.setStyleSheet(DATETIME_STYLE)
        self.dt_to.setFixedHeight(34)
        self.dt_to.setCalendarPopup(True)
        fbar.addWidget(self.dt_to)

        self.btn_apply = QPushButton("Apply")
        self.btn_apply.setStyleSheet(BUTTON_STYLE)
        self.btn_apply.setFixedHeight(34)
        self.btn_apply.clicked.connect(self.apply_filters)
        fbar.addWidget(self.btn_apply)

        self.btn_clear_filters = QPushButton("Clear Filters")
        self.btn_clear_filters.setStyleSheet(BUTTON_STYLE)
        self.btn_clear_filters.setFixedHeight(34)
        self.btn_clear_filters.clicked.connect(self._on_clear_filters)
        fbar.addWidget(self.btn_clear_filters)

        fbar.addStretch()
        root.addLayout(fbar)

        # ─── Action buttons ───
        abar = QHBoxLayout()
        abar.setSpacing(6)

        self.btn_clear_log = QPushButton("🗑  Clear Log")
        self.btn_clear_log.setStyleSheet(BUTTON_DANGER_STYLE)
        self.btn_clear_log.setFixedHeight(34)
        self.btn_clear_log.clicked.connect(self._on_clear_log)
        abar.addWidget(self.btn_clear_log)

        self.btn_csv = QPushButton("Export CSV")
        self.btn_csv.setStyleSheet(BUTTON_STYLE)
        self.btn_csv.setFixedHeight(34)
        self.btn_csv.clicked.connect(self.export_csv)
        abar.addWidget(self.btn_csv)

        self.btn_json = QPushButton("Export JSON")
        self.btn_json.setStyleSheet(BUTTON_STYLE)
        self.btn_json.setFixedHeight(34)
        self.btn_json.clicked.connect(self.export_json)
        abar.addWidget(self.btn_json)

        self.btn_txt = QPushButton("Export TXT")
        self.btn_txt.setStyleSheet(BUTTON_STYLE)
        self.btn_txt.setFixedHeight(34)
        self.btn_txt.clicked.connect(self.export_txt)
        abar.addWidget(self.btn_txt)

        abar.addStretch()
        root.addLayout(abar)

        # ─── Table ───
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setStyleSheet(TABLE_STYLE)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 110)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 110)
        root.addWidget(self.table, 1)

        # ─── Status bar ───
        self.lbl_status = QLabel("Showing 0 of 0 entries")
        self.lbl_status.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; padding: 2px 4px;")
        root.addWidget(self.lbl_status)

    # ── Public API ───────────────────────────────────────────────
    def add_log_entry(self, entry_dict: dict):
        """Append a log entry.

        Expected keys: timestamp, module, severity, description, source_ip, details
        """
        self._entries.append(entry_dict)
        self._insert_row(entry_dict, len(self._entries) - 1)
        self._update_status()
        self.table.scrollToBottom()

    def clear_log(self):
        """Remove all entries."""
        self.table.setRowCount(0)
        self._entries.clear()
        self._update_status()

    def apply_filters(self):
        """Show / hide rows based on current filter values."""
        mod_filter = self.combo_module.currentText()
        sev_filter = self.combo_severity.currentText()
        dt_from = self.dt_from.dateTime().toPyDateTime()
        dt_to = self.dt_to.dateTime().toPyDateTime()

        visible = 0
        for row in range(self.table.rowCount()):
            show = True

            # Module filter
            if mod_filter != "All":
                entry = self._entries[row] if row < len(self._entries) else {}
                if entry.get("module", "") != mod_filter:
                    show = False

            # Severity filter
            if show and sev_filter != "All":
                entry = self._entries[row] if row < len(self._entries) else {}
                if entry.get("severity", "").upper() != sev_filter:
                    show = False

            # Time range
            if show:
                entry = self._entries[row] if row < len(self._entries) else {}
                ts_str = entry.get("timestamp", "")
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if ts < dt_from or ts > dt_to:
                        show = False
                except (ValueError, TypeError):
                    pass  # Keep rows with unparseable timestamps visible

            self.table.setRowHidden(row, not show)
            if show:
                visible += 1

        self.lbl_status.setText(f"Showing {visible} of {len(self._entries)} entries")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "", "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.COLUMNS)
            for entry in self._visible_entries():
                writer.writerow([
                    entry.get("timestamp", ""),
                    entry.get("module", ""),
                    entry.get("severity", ""),
                    entry.get("description", ""),
                    entry.get("source_ip", ""),
                    entry.get("details", ""),
                ])

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "", "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(list(self._visible_entries()), f, indent=2, default=str)

    def export_txt(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export TXT", "", "Text Files (*.txt);;All Files (*)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for entry in self._visible_entries():
                ts = entry.get("timestamp", "")
                mod = entry.get("module", "")
                sev = entry.get("severity", "")
                desc = entry.get("description", "")
                src = entry.get("source_ip", "")
                det = entry.get("details", "")
                f.write(f"[{ts}] [{mod}] [{sev}] {desc} (src={src}) {det}\n")

    def save_to_file(self, filepath: str):
        """Persist all entries to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2, default=str)

    def load_from_file(self, filepath: str):
        """Load entries from a previously saved JSON file."""
        if not os.path.exists(filepath):
            return
        with open(filepath, "r", encoding="utf-8") as f:
            entries = json.load(f)
        self.clear_log()
        for entry in entries:
            self.add_log_entry(entry)

    # ── Private ──────────────────────────────────────────────────
    def _insert_row(self, entry: dict, _idx: int):
        row = self.table.rowCount()
        self.table.insertRow(row)

        # Timestamp
        self.table.setItem(row, 0, QTableWidgetItem(str(entry.get("timestamp", ""))))

        # Module badge
        module = entry.get("module", "")
        badge_m = _module_badge(module)
        self.table.setCellWidget(row, 1, badge_m)

        # Severity badge
        severity = entry.get("severity", "INFO").upper()
        badge_s = _severity_badge(severity)
        self.table.setCellWidget(row, 2, badge_s)

        # Description
        self.table.setItem(row, 3, QTableWidgetItem(str(entry.get("description", ""))))

        # Source IP
        self.table.setItem(row, 4, QTableWidgetItem(str(entry.get("source_ip", ""))))

        # Details
        self.table.setItem(row, 5, QTableWidgetItem(str(entry.get("details", ""))))

    def _update_status(self):
        visible = sum(1 for r in range(self.table.rowCount()) if not self.table.isRowHidden(r))
        total = len(self._entries)
        self.lbl_status.setText(f"Showing {visible} of {total} entries")

    def _visible_entries(self):
        """Yield entries whose table rows are currently visible."""
        for row in range(self.table.rowCount()):
            if not self.table.isRowHidden(row) and row < len(self._entries):
                yield self._entries[row]

    def _on_clear_filters(self):
        self.combo_module.setCurrentIndex(0)
        self.combo_severity.setCurrentIndex(0)
        self.dt_from.setDateTime(QDateTime.currentDateTime().addDays(-1))
        self.dt_to.setDateTime(QDateTime.currentDateTime())
        # Un-hide all rows
        for r in range(self.table.rowCount()):
            self.table.setRowHidden(r, False)
        self._update_status()

    def _on_clear_log(self):
        reply = QMessageBox.question(
            self,
            "Clear Log",
            "Are you sure you want to clear the entire log?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.clear_log()
