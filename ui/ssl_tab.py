"""
NetWraith — SSL Tab
SSL/TLS certificate inspector with bulk import, flag badges,
detail panel, and JSON export.
"""

import json
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QSplitter, QFileDialog, QAbstractItemView, QFrame,
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

DETAIL_STYLE = f"""
QTextEdit {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    padding: 8px;
}}
"""

# ── Flag badge config ────────────────────────────────────────────
FLAG_CONFIG = {
    "EXPIRED":           (DANGER_RED,    "#3a1414"),
    "EXPIRING SOON":     (WARNING_AMBER, "#3a2e14"),
    "SELF-SIGNED":       (ACCENT_CYAN,   "#0a2a30"),
    "WEAK SIGNATURE":    (DANGER_RED,    "#3a1414"),
    "HOSTNAME MISMATCH": (DANGER_RED,    "#3a1414"),
    "VALID":             (SUCCESS_GREEN, "#143a1a"),
}


def _make_flags_widget(flags: list[str]) -> QWidget:
    """Return a widget containing horizontally arranged flag badges."""
    container = QWidget()
    container.setStyleSheet("background: transparent;")
    lay = QHBoxLayout(container)
    lay.setContentsMargins(4, 2, 4, 2)
    lay.setSpacing(4)

    for flag in flags:
        fg, bg = FLAG_CONFIG.get(flag.upper(), (TEXT_SECONDARY, "#2a2d35"))
        lbl = QLabel(flag.upper())
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                color: {fg};
                border-radius: 8px;
                padding: 2px 8px;
                font-weight: bold;
                font-size: 11px;
            }}
        """)
        lay.addWidget(lbl)
    lay.addStretch()
    return container


class SSLTab(QWidget):
    """SSL/TLS certificate inspector tab."""

    inspect_requested = pyqtSignal(list)  # list of target strings

    COLUMNS = [
        "Target", "Subject CN", "Issuer", "Valid From", "Valid To",
        "Days Left", "SANs", "Key Algo", "Sig Algo", "Flags",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
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

        self.input_target = QLineEdit()
        self.input_target.setPlaceholderText("host:port or IP:443")
        self.input_target.setStyleSheet(LINE_EDIT_STYLE)
        self.input_target.setFixedHeight(34)
        self.input_target.setMinimumWidth(240)
        bar.addWidget(self.input_target, 1)

        self.btn_inspect = QPushButton("🔒  Inspect")
        self.btn_inspect.setStyleSheet(BUTTON_SUCCESS_STYLE)
        self.btn_inspect.setFixedHeight(34)
        self.btn_inspect.clicked.connect(self._on_inspect)
        bar.addWidget(self.btn_inspect)

        self.btn_bulk = QPushButton("📂  Bulk Import")
        self.btn_bulk.setStyleSheet(BUTTON_STYLE)
        self.btn_bulk.setFixedHeight(34)
        self.btn_bulk.clicked.connect(self._on_bulk_import)
        bar.addWidget(self.btn_bulk)

        self.btn_export = QPushButton("Export JSON")
        self.btn_export.setStyleSheet(BUTTON_STYLE)
        self.btn_export.setFixedHeight(34)
        self.btn_export.clicked.connect(self._on_export_json)
        bar.addWidget(self.btn_export)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.setStyleSheet(f"""
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
        """)
        self.btn_clear.setFixedHeight(34)
        self.btn_clear.clicked.connect(self.clear_results)
        bar.addWidget(self.btn_clear)

        root.addLayout(bar)

        # ─── Splitter: table + detail panel ───
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                height: 3px;
            }}
        """)

        # ── Table ──
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
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self.table)

        # ── Detail panel ──
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {BG_PANEL};
                border: 1px solid {BORDER_COLOR};
                border-radius: 4px;
            }}
        """)
        df_lay = QVBoxLayout(detail_frame)
        df_lay.setContentsMargins(10, 8, 10, 8)
        df_lay.setSpacing(4)

        detail_title = QLabel("🔐  Certificate Details")
        detail_title.setStyleSheet(f"color: {ACCENT_CYAN}; font-weight: bold; font-size: 14px; border: none;")
        df_lay.addWidget(detail_title)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet(DETAIL_STYLE)
        df_lay.addWidget(self.detail_text)

        splitter.addWidget(detail_frame)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

        # ── Counter ──
        self.lbl_count = QLabel("0 certificates inspected")
        self.lbl_count.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; padding: 2px 4px;")
        root.addWidget(self.lbl_count)

    # ── Public API ───────────────────────────────────────────────
    def add_cert_result(self, result_dict: dict):
        """Append a certificate inspection result.

        Expected keys: target, subject_cn, issuer, valid_from, valid_to,
                       days_left, sans, key_algo, sig_algo, flags,
                       full_detail (str for detail panel)
        """
        self._results.append(result_dict)
        row = self.table.rowCount()
        self.table.insertRow(row)

        text_keys = [
            "target", "subject_cn", "issuer", "valid_from", "valid_to",
            "days_left", "sans", "key_algo", "sig_algo",
        ]
        for col, key in enumerate(text_keys):
            val = result_dict.get(key, "")
            item = QTableWidgetItem(str(val))

            # Colour days_left based on urgency
            if key == "days_left":
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                try:
                    d = int(val)
                    if d <= 0:
                        item.setForeground(QColor(DANGER_RED))
                    elif d <= 30:
                        item.setForeground(QColor(WARNING_AMBER))
                    else:
                        item.setForeground(QColor(SUCCESS_GREEN))
                except (ValueError, TypeError):
                    pass

            self.table.setItem(row, col, item)

        # Flags column – composite badges
        flags = result_dict.get("flags", [])
        if isinstance(flags, str):
            flags = [f.strip() for f in flags.split(",") if f.strip()]
        if not flags:
            flags = ["VALID"]
        flags_widget = _make_flags_widget(flags)
        self.table.setCellWidget(row, 9, flags_widget)

        # Store full detail for click
        first_item = self.table.item(row, 0)
        if first_item:
            first_item.setData(Qt.ItemDataRole.UserRole, result_dict.get("full_detail", ""))

        self.lbl_count.setText(f"{self.table.rowCount()} certificates inspected")
        self.table.scrollToBottom()

    def clear_results(self):
        """Clear all results."""
        self.table.setRowCount(0)
        self._results.clear()
        self.detail_text.clear()
        self.lbl_count.setText("0 certificates inspected")

    # ── Private ──────────────────────────────────────────────────
    def _on_inspect(self):
        target = self.input_target.text().strip()
        if target:
            self.inspect_requested.emit([target])

    def _on_bulk_import(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Target List", "",
            "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip()]
        if targets:
            self.inspect_requested.emit(targets)

    def _on_export_json(self):
        if not self._results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "",
            "JSON Files (*.json);;All Files (*)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._results, f, indent=2, default=str)

    def _on_row_selected(self, row, _col, _prev_row, _prev_col):
        if row < 0:
            return
        first_item = self.table.item(row, 0)
        if first_item:
            detail = first_item.data(Qt.ItemDataRole.UserRole)
            if detail:
                self.detail_text.setPlainText(str(detail))
            else:
                # Build detail from stored result
                if row < len(self._results):
                    r = self._results[row]
                    lines = []
                    for k, v in r.items():
                        if k != "full_detail":
                            lines.append(f"{k:20s}: {v}")
                    self.detail_text.setPlainText("\n".join(lines))
