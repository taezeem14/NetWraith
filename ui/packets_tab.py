"""
NetWraith — Packets Tab
Real-time packet inspector with BPF filter, protocol-colored table,
and detail panel (Layers / Hex Dump / Decoded).
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QTextEdit, QFileDialog,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon

# ── Theme constants ──────────────────────────────────────────────
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

# Protocol → colour mapping
PROTO_COLORS = {
    "TCP":   "#4fc3f7",
    "UDP":   ACCENT_CYAN,
    "ICMP":  WARNING_AMBER,
    "ARP":   SUCCESS_GREEN,
    "DNS":   PURPLE,
}
PROTO_DEFAULT_COLOR = TEXT_SECONDARY

# ── Shared stylesheet fragments ─────────────────────────────────
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

TREE_STYLE = f"""
QTreeWidget {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    font-size: 13px;
}}
QTreeWidget::item {{
    padding: 3px 0px;
}}
QTreeWidget::item:selected {{
    background-color: rgba(0, 229, 255, 0.15);
    color: {ACCENT_CYAN};
}}
QHeaderView::section {{
    background-color: {BG_PANEL};
    color: {ACCENT_CYAN};
    border: 1px solid {BORDER_COLOR};
    padding: 5px 8px;
    font-weight: bold;
}}
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {{
    border-image: none;
    image: none;
}}
QTreeWidget::branch:open:has-children:!has-siblings,
QTreeWidget::branch:open:has-children:has-siblings {{
    border-image: none;
    image: none;
}}
"""

TEXTEDIT_STYLE = f"""
QTextEdit {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    padding: 6px;
}}
"""

TAB_WIDGET_STYLE = f"""
QTabWidget::pane {{
    border: 1px solid {BORDER_COLOR};
    background-color: {BG_DARK};
}}
QTabBar::tab {{
    background-color: {BG_PANEL};
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER_COLOR};
    border-bottom: none;
    padding: 6px 16px;
    margin-right: 2px;
    font-size: 13px;
}}
QTabBar::tab:selected {{
    background-color: {BG_DARK};
    color: {ACCENT_CYAN};
    border-bottom: 2px solid {ACCENT_CYAN};
}}
QTabBar::tab:hover:!selected {{
    background-color: rgba(0, 229, 255, 0.06);
    color: {TEXT_PRIMARY};
}}
"""


class PacketsTab(QWidget):
    """Real-time packet inspector tab."""

    capture_toggled = pyqtSignal(bool)
    filter_applied = pyqtSignal(str)

    # ── columns ──
    COLUMNS = ["#", "Timestamp", "Source IP", "Dst IP", "Protocol", "Length", "Info"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._capturing = False
        self._packet_count = 0
        self.setup_ui()

    # ── UI construction ──────────────────────────────────────────
    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ─── Top control bar ───
        bar = QHBoxLayout()
        bar.setSpacing(6)

        self.btn_toggle = QPushButton("▶  Start Capture")
        self.btn_toggle.setStyleSheet(BUTTON_SUCCESS_STYLE)
        self.btn_toggle.setFixedHeight(34)
        self.btn_toggle.clicked.connect(self._on_toggle)
        bar.addWidget(self.btn_toggle)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g. tcp port 80")
        self.filter_input.setStyleSheet(LINE_EDIT_STYLE)
        self.filter_input.setFixedHeight(34)
        self.filter_input.setMinimumWidth(220)
        bar.addWidget(self.filter_input, 1)

        self.btn_apply_filter = QPushButton("Apply Filter")
        self.btn_apply_filter.setStyleSheet(BUTTON_STYLE)
        self.btn_apply_filter.setFixedHeight(34)
        self.btn_apply_filter.clicked.connect(self._on_apply_filter)
        bar.addWidget(self.btn_apply_filter)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.setStyleSheet(BUTTON_DANGER_STYLE)
        self.btn_clear.setFixedHeight(34)
        self.btn_clear.clicked.connect(self.clear_packets)
        bar.addWidget(self.btn_clear)

        self.btn_save = QPushButton("💾  Save .pcap")
        self.btn_save.setStyleSheet(BUTTON_STYLE)
        self.btn_save.setFixedHeight(34)
        self.btn_save.clicked.connect(self._on_save_pcap)
        bar.addWidget(self.btn_save)

        root.addLayout(bar)

        # ─── Splitter: table (top) + detail panel (bottom) ───
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {BORDER_COLOR};
                height: 3px;
            }}
        """)

        # ── Packet table ──
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
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.currentCellChanged.connect(self._on_row_selected)
        splitter.addWidget(self.table)

        # ── Detail panel (sub-tabs) ──
        self.detail_tabs = QTabWidget()
        self.detail_tabs.setStyleSheet(TAB_WIDGET_STYLE)

        # Layers tree
        self.layers_tree = QTreeWidget()
        self.layers_tree.setHeaderLabels(["Layer / Field", "Value"])
        self.layers_tree.setStyleSheet(TREE_STYLE)
        self.layers_tree.setAlternatingRowColors(True)
        self.layers_tree.header().setStretchLastSection(True)
        self.detail_tabs.addTab(self.layers_tree, "Layers")

        # Hex dump
        self.hex_edit = QTextEdit()
        self.hex_edit.setReadOnly(True)
        self.hex_edit.setStyleSheet(TEXTEDIT_STYLE)
        self.detail_tabs.addTab(self.hex_edit, "Hex Dump")

        # Decoded
        self.decoded_edit = QTextEdit()
        self.decoded_edit.setReadOnly(True)
        self.decoded_edit.setStyleSheet(TEXTEDIT_STYLE)
        self.detail_tabs.addTab(self.decoded_edit, "Decoded")

        splitter.addWidget(self.detail_tabs)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

        # ─── Bottom counter ───
        self.lbl_counter = QLabel("Captured: 0 packets")
        self.lbl_counter.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; padding: 2px 4px;")
        root.addWidget(self.lbl_counter)

    # ── Public API ───────────────────────────────────────────────
    def add_packet(self, pkt_dict: dict):
        """Append a packet row.

        Expected keys: number, timestamp, src, dst, protocol, length, info
        Optional: detail (dict for detail panel)
        """
        row = self.table.rowCount()
        self.table.insertRow(row)

        values = [
            str(pkt_dict.get("number", row + 1)),
            str(pkt_dict.get("timestamp", "")),
            str(pkt_dict.get("src", "")),
            str(pkt_dict.get("dst", "")),
            str(pkt_dict.get("protocol", "")),
            str(pkt_dict.get("length", "")),
            str(pkt_dict.get("info", "")),
        ]

        proto = pkt_dict.get("protocol", "").upper()
        proto_color = QColor(PROTO_COLORS.get(proto, PROTO_DEFAULT_COLOR))

        for col, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            if col == 4:  # Protocol column
                item.setForeground(proto_color)
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.table.setItem(row, col, item)

        # Store detail dict on row for later retrieval
        first_item = self.table.item(row, 0)
        if first_item:
            first_item.setData(Qt.ItemDataRole.UserRole, pkt_dict.get("detail"))

        self._packet_count += 1
        self.lbl_counter.setText(f"Captured: {self._packet_count} packets")
        self.table.scrollToBottom()

    def show_packet_detail(self, detail_dict: dict):
        """Populate the detail sub-tabs from a detail dictionary.

        Expected keys:
          layers: list of dicts  {name, fields: [{name, value}]}
          hex_dump: str
          decoded: str
        """
        if not detail_dict:
            return

        # ── Layers ──
        self.layers_tree.clear()
        for layer in detail_dict.get("layers", []):
            parent = QTreeWidgetItem([layer.get("name", "Unknown"), ""])
            parent.setForeground(0, QColor(ACCENT_CYAN))
            font = parent.font(0)
            font.setBold(True)
            parent.setFont(0, font)
            for field in layer.get("fields", []):
                child = QTreeWidgetItem([field.get("name", ""), str(field.get("value", ""))])
                child.setForeground(0, QColor(TEXT_SECONDARY))
                child.setForeground(1, QColor(TEXT_PRIMARY))
                parent.addChild(child)
            self.layers_tree.addTopLevelItem(parent)
        self.layers_tree.expandAll()

        # ── Hex dump ──
        self.hex_edit.setPlainText(detail_dict.get("hex_dump", ""))

        # ── Decoded ──
        self.decoded_edit.setPlainText(detail_dict.get("decoded", ""))

    def clear_packets(self):
        """Remove all packet rows and reset counter."""
        self.table.setRowCount(0)
        self._packet_count = 0
        self.lbl_counter.setText("Captured: 0 packets")
        self.layers_tree.clear()
        self.hex_edit.clear()
        self.decoded_edit.clear()

    def set_capturing(self, capturing: bool):
        """Update button state to reflect capture status."""
        self._capturing = capturing
        if capturing:
            self.btn_toggle.setText("■  Stop Capture")
            self.btn_toggle.setStyleSheet(BUTTON_DANGER_STYLE)
        else:
            self.btn_toggle.setText("▶  Start Capture")
            self.btn_toggle.setStyleSheet(BUTTON_SUCCESS_STYLE)

    # ── Internal slots ───────────────────────────────────────────
    def _on_toggle(self):
        new_state = not self._capturing
        self.set_capturing(new_state)
        self.capture_toggled.emit(new_state)

    def _on_apply_filter(self):
        self.filter_applied.emit(self.filter_input.text().strip())

    def _on_row_selected(self, row, _col, _prev_row, _prev_col):
        if row < 0:
            return
        first_item = self.table.item(row, 0)
        if first_item:
            detail = first_item.data(Qt.ItemDataRole.UserRole)
            if detail:
                self.show_packet_detail(detail)

    def _on_save_pcap(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Packet Capture", "", "PCAP Files (*.pcap);;All Files (*)"
        )
        # Actual saving would be handled by the engine via signal;
        # store path for external consumption.
        if path:
            self._last_save_path = path
