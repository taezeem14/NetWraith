"""
NetWraith — Ports Tab
Multi-threaded port scanner UI with scan controls, result table,
progress bar, and CSV / JSON export.
"""

import csv
import json
import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QSlider, QProgressBar, QFileDialog, QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal
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

LINE_EDIT_STYLE = f"""
QLineEdit {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 13px;
    selection-background-color: {ACCENT_CYAN};
    selection-color: {BG_DARK};
}}
QLineEdit:focus {{
    border-color: {ACCENT_CYAN};
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
    min-width: 120px;
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

SLIDER_STYLE = f"""
QSlider::groove:horizontal {{
    background: {BG_DARK};
    border: 1px solid {BORDER_COLOR};
    height: 6px;
    border-radius: 3px;
}}
QSlider::handle:horizontal {{
    background: {ACCENT_CYAN};
    border: none;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}}
QSlider::sub-page:horizontal {{
    background: {ACCENT_CYAN};
    border-radius: 3px;
}}
QSlider::add-page:horizontal {{
    background: {BG_DARK};
    border: 1px solid {BORDER_COLOR};
    border-radius: 3px;
}}
"""

PROGRESS_STYLE = f"""
QProgressBar {{
    background-color: {BG_DARK};
    border: 1px solid {BORDER_COLOR};
    border-radius: 4px;
    text-align: center;
    color: {TEXT_PRIMARY};
    font-size: 12px;
    height: 20px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT_CYAN};
    border-radius: 3px;
}}
"""

# ── State badge helpers ──────────────────────────────────────────
STATE_STYLES = {
    "OPEN": (SUCCESS_GREEN, "#143a1a"),
    "CLOSED": (DANGER_RED, "#3a1414"),
    "FILTERED": (TEXT_SECONDARY, "#2a2d35"),
}


def _state_widget(state: str) -> QLabel:
    fg, bg = STATE_STYLES.get(state.upper(), (TEXT_SECONDARY, "#2a2d35"))
    lbl = QLabel(state.upper())
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


class PortsTab(QWidget):
    """Multi-threaded port scanner tab."""

    scan_requested = pyqtSignal(str, tuple, str, int)  # target, (start, end), scan_type, threads

    COLUMNS = ["Port", "Protocol", "State", "Service", "Banner"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scanning = False
        self._results: list[dict] = []
        self.setup_ui()

    # ── UI ───────────────────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ─── Top bar ───
        bar = QHBoxLayout()
        bar.setSpacing(6)

        lbl_target = QLabel("Target:")
        lbl_target.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        bar.addWidget(lbl_target)

        self.input_target = QLineEdit()
        self.input_target.setPlaceholderText("192.168.1.1")
        self.input_target.setStyleSheet(LINE_EDIT_STYLE)
        self.input_target.setFixedHeight(34)
        self.input_target.setFixedWidth(160)
        bar.addWidget(self.input_target)

        lbl_ports = QLabel("Ports:")
        lbl_ports.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        bar.addWidget(lbl_ports)

        self.input_ports = QLineEdit("1-1024")
        self.input_ports.setStyleSheet(LINE_EDIT_STYLE)
        self.input_ports.setFixedHeight(34)
        self.input_ports.setFixedWidth(110)
        bar.addWidget(self.input_ports)

        lbl_type = QLabel("Type:")
        lbl_type.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        bar.addWidget(lbl_type)

        self.combo_type = QComboBox()
        self.combo_type.addItems(["TCP Connect", "SYN Scan", "UDP Scan"])
        self.combo_type.setStyleSheet(COMBO_STYLE)
        self.combo_type.setFixedHeight(34)
        bar.addWidget(self.combo_type)

        lbl_threads = QLabel("Threads:")
        lbl_threads.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        bar.addWidget(lbl_threads)

        self.slider_threads = QSlider(Qt.Orientation.Horizontal)
        self.slider_threads.setRange(1, 500)
        self.slider_threads.setValue(100)
        self.slider_threads.setFixedWidth(120)
        self.slider_threads.setStyleSheet(SLIDER_STYLE)
        self.slider_threads.valueChanged.connect(self._on_slider_changed)
        bar.addWidget(self.slider_threads)

        self.lbl_thread_val = QLabel("100")
        self.lbl_thread_val.setFixedWidth(36)
        self.lbl_thread_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_thread_val.setStyleSheet(f"color: {ACCENT_CYAN}; font-size: 13px; font-weight: bold;")
        bar.addWidget(self.lbl_thread_val)

        self.btn_scan = QPushButton("🔍  Scan")
        self.btn_scan.setStyleSheet(BUTTON_SUCCESS_STYLE)
        self.btn_scan.setFixedHeight(34)
        self.btn_scan.clicked.connect(self._on_scan)
        bar.addWidget(self.btn_scan)

        self.btn_export = QPushButton("Export")
        self.btn_export.setStyleSheet(BUTTON_STYLE)
        self.btn_export.setFixedHeight(34)
        self.btn_export.clicked.connect(self._on_export)
        bar.addWidget(self.btn_export)

        bar.addStretch()
        root.addLayout(bar)

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
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(2, 110)
        root.addWidget(self.table, 1)

        # ─── Progress bar ───
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet(PROGRESS_STYLE)
        self.progress.setFixedHeight(22)
        root.addWidget(self.progress)

        # ─── Summary label ───
        self.lbl_summary = QLabel("Ready")
        self.lbl_summary.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; padding: 2px 4px;")
        root.addWidget(self.lbl_summary)

    # ── Public API ───────────────────────────────────────────────
    def add_port_result(self, result_dict: dict):
        """Append a scan result row.

        Expected keys: port, protocol, state, service, banner
        """
        self._results.append(result_dict)
        row = self.table.rowCount()
        self.table.insertRow(row)

        port_item = QTableWidgetItem(str(result_dict.get("port", "")))
        port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 0, port_item)

        proto_item = QTableWidgetItem(result_dict.get("protocol", "TCP").upper())
        proto_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table.setItem(row, 1, proto_item)

        # State badge
        state = result_dict.get("state", "CLOSED").upper()
        badge = _state_widget(state)
        self.table.setCellWidget(row, 2, badge)

        self.table.setItem(row, 3, QTableWidgetItem(result_dict.get("service", "")))
        self.table.setItem(row, 4, QTableWidgetItem(result_dict.get("banner", "")))

        self._update_summary()

    def set_progress(self, current: int, total: int):
        """Update the progress bar."""
        if total > 0:
            self.progress.setMaximum(total)
            self.progress.setValue(current)
            pct = int(current / total * 100)
            self.progress.setFormat(f"{current}/{total}  ({pct}%)")
        else:
            self.progress.setMaximum(0)

    def clear_results(self):
        """Clear the results table."""
        self.table.setRowCount(0)
        self._results.clear()
        self.progress.setValue(0)
        self.progress.setFormat("")
        self.lbl_summary.setText("Ready")

    def set_scanning(self, scanning: bool):
        """Toggle button state."""
        self._scanning = scanning
        if scanning:
            self.btn_scan.setText("■  Stop")
            self.btn_scan.setStyleSheet(BUTTON_DANGER_STYLE)
            self.input_target.setEnabled(False)
            self.input_ports.setEnabled(False)
            self.combo_type.setEnabled(False)
            self.slider_threads.setEnabled(False)
        else:
            self.btn_scan.setText("🔍  Scan")
            self.btn_scan.setStyleSheet(BUTTON_SUCCESS_STYLE)
            self.input_target.setEnabled(True)
            self.input_ports.setEnabled(True)
            self.combo_type.setEnabled(True)
            self.slider_threads.setEnabled(True)

    # ── Internal ─────────────────────────────────────────────────
    def _parse_port_range(self) -> tuple[int, int]:
        text = self.input_ports.text().strip()
        if "-" in text:
            parts = text.split("-", 1)
            return int(parts[0].strip()), int(parts[1].strip())
        return int(text), int(text)

    def _on_slider_changed(self, value: int):
        self.lbl_thread_val.setText(str(value))

    def _on_scan(self):
        if self._scanning:
            self.set_scanning(False)
            return
        target = self.input_target.text().strip()
        if not target:
            return
        port_range = self._parse_port_range()
        scan_type = self.combo_type.currentText()
        threads = self.slider_threads.value()
        self.clear_results()
        self.set_scanning(True)
        self.scan_requested.emit(target, port_range, scan_type, threads)

    def _on_export(self):
        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Results", "",
            "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        if path.endswith(".json") or "JSON" in selected_filter:
            self._export_json(path)
        else:
            self._export_csv(path)

    def _export_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.COLUMNS)
            for r in self._results:
                writer.writerow([
                    r.get("port", ""),
                    r.get("protocol", ""),
                    r.get("state", ""),
                    r.get("service", ""),
                    r.get("banner", ""),
                ])

    def _export_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._results, f, indent=2)

    def _update_summary(self):
        open_c = sum(1 for r in self._results if r.get("state", "").upper() == "OPEN")
        closed_c = sum(1 for r in self._results if r.get("state", "").upper() == "CLOSED")
        filtered_c = sum(1 for r in self._results if r.get("state", "").upper() == "FILTERED")
        self.lbl_summary.setText(
            f"<span style='color:{SUCCESS_GREEN}'>{open_c} open</span>, "
            f"<span style='color:{DANGER_RED}'>{closed_c} closed</span>, "
            f"<span style='color:{TEXT_SECONDARY}'>{filtered_c} filtered</span> ports"
        )
