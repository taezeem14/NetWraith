"""
NetWraith — Threat Intelligence Tab
===================================

Visualizes resolved public IP destinations captured in real-time, displays
reputation scores, GeoIP location, ISP details, and flags suspicious activity.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QLabel, QAbstractItemView,
    QFrame, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont

# Theme Constants
BG_DARK = "#0d0f14"
BG_PANEL = "#1a1d24"
ACCENT_CYAN = "#00e5ff"
BORDER_COLOR = "#2a2d35"
TEXT_PRIMARY = "#ffffff"
TEXT_SECONDARY = "#8a8f98"
SUCCESS_GREEN = "#4caf50"
WARNING_AMBER = "#ffb74d"
DANGER_RED = "#ff4c4c"

_COLUMNS = ["IP Address", "Country", "ISP", "Threat Rating", "Packets Captured", "Last Seen"]

class ThreatIntelTab(QWidget):
    """Real-time public IP destination profiling and threat intelligence workspace."""

    monitoring_toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._ip_row_map: dict[str, int] = {}
        self._ip_data_cache: dict[str, dict] = {}
        self._is_monitoring = False
        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # ── Top Control Bar ──
        bar = QHBoxLayout()
        self.btn_monitor = QPushButton("🌍  Start Threat Monitoring")
        self.btn_monitor.setCheckable(True)
        self.btn_monitor.setCursor(Qt.CursorShape.PointingHandCursor)
        self.set_monitoring(False)
        self.btn_monitor.clicked.connect(self._on_monitor_clicked)
        bar.addWidget(self.btn_monitor)

        self.lbl_status = QLabel("Monitoring offline — external destination tracking paused.")
        self.lbl_status.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px; padding-left: 10px;")
        bar.addWidget(self.lbl_status)
        bar.addStretch()
        
        self.btn_clear = QPushButton("🗑  Clear Table")
        self.btn_clear.setStyleSheet(f"""
            QPushButton {{
                background-color: {BG_PANEL};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #252830;
                border-color: {ACCENT_CYAN};
            }}
        """)
        self.btn_clear.clicked.connect(self.clear_table)
        bar.addWidget(self.btn_clear)
        root.addLayout(bar)

        # ── Splitter ──
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BORDER_COLOR}; width: 3px; }}")

        # Table Panel
        tbl_frame = QFrame()
        tbl_frame.setStyleSheet(f"border: 1px solid {BORDER_COLOR}; border-radius: 8px; background-color: {BG_PANEL};")
        tbl_lay = QVBoxLayout(tbl_frame)
        tbl_lay.setContentsMargins(8, 8, 8, 8)

        tbl_title = QLabel("📡  External Destination Tracker")
        tbl_title.setStyleSheet("color: #ffffff; font-weight: bold; border: none; font-size: 13px; padding-bottom: 4px;")
        tbl_lay.addWidget(tbl_title)

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
                border: 1px solid {BORDER_COLOR};
            }}
        """)
        
        self.table.itemSelectionChanged.connect(self._on_row_selected)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        tbl_lay.addWidget(self.table)
        splitter.addWidget(tbl_frame)

        # Details Sidebar
        det_frame = QFrame()
        det_frame.setStyleSheet(f"border: 1px solid {BORDER_COLOR}; border-radius: 8px; background-color: {BG_PANEL};")
        det_lay = QVBoxLayout(det_frame)
        det_lay.setContentsMargins(12, 12, 12, 12)
        det_lay.setSpacing(10)

        det_title = QLabel("🔍  IP Threat Dossier")
        det_title.setStyleSheet("color: #ffffff; font-weight: bold; border: none; font-size: 13px;")
        det_lay.addWidget(det_title)

        self.details_area = QTextEdit()
        self.details_area.setReadOnly(True)
        self.details_area.setStyleSheet(f"""
            QTextEdit {{
                background-color: {BG_DARK};
                color: {TEXT_PRIMARY};
                border: 1px solid {BORDER_COLOR};
                border-radius: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.5;
            }}
        """)
        self.details_area.setHtml("<p style='color:#8a8f98;'>Select resolved external host IP to inspect security intelligence.</p>")
        det_lay.addWidget(self.details_area)

        splitter.addWidget(det_frame)
        splitter.setSizes([750, 400])
        root.addWidget(splitter, 1)

    def set_monitoring(self, active: bool):
        self._is_monitoring = active
        self.btn_monitor.setChecked(active)
        if active:
            self.btn_monitor.setText("⏹  Stop Threat Monitoring")
            self.btn_monitor.setStyleSheet(f"""
                QPushButton {{
                    background-color: {DANGER_RED};
                    color: {TEXT_PRIMARY};
                    border: none;
                    border-radius: 6px;
                    padding: 10px 24px;
                    font-size: 13px;
                    font-weight: bold;
                }}
                QPushButton:hover {{ background-color: #ff6b6b; }}
            """)
            self.lbl_status.setText("Real-time public IP profiling is active. Inspecting connections...")
        else:
            self.btn_monitor.setText("🌍  Start Threat Monitoring")
            self.btn_monitor.setStyleSheet(f"""
                QPushButton {{
                    background-color: {SUCCESS_GREEN};
                    color: {TEXT_PRIMARY};
                    border: none;
                    border-radius: 6px;
                    padding: 10px 24px;
                    font-size: 13px;
                    font-weight: bold;
                }}
                QPushButton:hover {{ background-color: #66bb6a; }}
            """)
            self.lbl_status.setText("Monitoring offline — external destination tracking paused.")

    def clear_table(self):
        self.table.setRowCount(0)
        self._ip_row_map.clear()
        self._ip_data_cache.clear()
        self.details_area.setHtml("<p style='color:#8a8f98;'>Select resolved external host IP to inspect security intelligence.</p>")

    def _on_monitor_clicked(self):
        self.monitoring_toggled.emit(self.btn_monitor.isChecked())

    def update_intel(self, data: dict):
        """Update table and cache with resolved threat details from backend thread."""
        ip = data.get("ip")
        if not ip:
            return

        self._ip_data_cache[ip] = data

        def _item(text: str, is_bold=False) -> QTableWidgetItem:
            item = QTableWidgetItem(str(text))
            item.setForeground(QColor(TEXT_PRIMARY))
            if is_bold:
                item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            return item

        score = data.get("threat_score", 0)
        rating_color = SUCCESS_GREEN if score < 20 else (WARNING_AMBER if score < 50 else DANGER_RED)
        
        rating_item = QTableWidgetItem(f" {score}/100 ")
        rating_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        rating_item.setForeground(QColor(BG_DARK))
        rating_item.setBackground(QColor(rating_color))
        rating_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        rating_item.setFlags(rating_item.flags() & ~Qt.ItemFlag.ItemIsEditable)

        if ip in self._ip_row_map:
            # Update existing row
            row = self._ip_row_map[ip]
            self.table.setItem(row, 1, _item(data.get("country", "Unknown")))
            self.table.setItem(row, 2, _item(data.get("isp", "Unknown")))
            self.table.setItem(row, 3, rating_item)
            # Retain captured count
            cap_item = self.table.item(row, 4)
            cnt = int(cap_item.text()) if cap_item else 1
            self.table.setItem(row, 4, _item(str(cnt), is_bold=True))
            self.table.setItem(row, 5, _item(data.get("timestamp", "").split("T")[-1][:8]))
        else:
            # Add new row
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._ip_row_map[ip] = row
            
            self.table.setItem(row, 0, _item(ip))
            self.table.setItem(row, 1, _item(data.get("country", "Unknown")))
            self.table.setItem(row, 2, _item(data.get("isp", "Unknown")))
            self.table.setItem(row, 3, rating_item)
            self.table.setItem(row, 4, _item("1", is_bold=True))
            self.table.setItem(row, 5, _item(data.get("timestamp", "").split("T")[-1][:8]))

        # Refresh details if this row is selected
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows and selected_rows[0].row() == row:
            self._on_row_selected()

    def add_external_ip(self, ip: str):
        """Called directly by packet capturer when it sees public IP packets."""
        if not self._is_monitoring:
            return

        if ip in self._ip_row_map:
            row = self._ip_row_map[ip]
            cap_item = self.table.item(row, 4)
            count = int(cap_item.text()) if cap_item else 0
            count += 1
            
            def _item(text: str) -> QTableWidgetItem:
                item = QTableWidgetItem(str(text))
                item.setForeground(QColor(TEXT_PRIMARY))
                item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                return item

            self.table.setItem(row, 4, _item(str(count)))

    def _on_row_selected(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return

        row = selected[0].row()
        ip_item = self.table.item(row, 0)
        if not ip_item:
            return
        
        ip = ip_item.text()
        data = self._ip_data_cache.get(ip)
        if not data:
            self.details_area.setHtml(f"<h4>IP Address: {ip}</h4><p style='color:#8a8f98;'>Queued for resolution...</p>")
            return

        score = data.get("threat_score", 0)
        score_color = SUCCESS_GREEN if score < 20 else (WARNING_AMBER if score < 50 else DANGER_RED)
        
        html = f"""
        <h3 style='color:{ACCENT_CYAN}; margin:0;'>🌍 Host: {data.get("ip")}</h3>
        <hr style='border-color:{BORDER_COLOR};'>
        <table width='100%' cellpadding='4' style='color:{TEXT_PRIMARY}; font-size:12px;'>
            <tr><td><b>Country:</b></td><td style='color:#ffffff;'>{data.get("country")}</td></tr>
            <tr><td><b>Region:</b></td><td style='color:#ffffff;'>{data.get("region")}</td></tr>
            <tr><td><b>ISP Provider:</b></td><td style='color:#ffffff;'>{data.get("isp")}</td></tr>
            <tr><td><b>Organization:</b></td><td style='color:#ffffff;'>{data.get("org")}</td></tr>
            <tr>
                <td><b>Threat Level:</b></td>
                <td><b style='color:{score_color};'>{score}%</b></td>
            </tr>
            <tr><td><b>Flags:</b></td><td style='color:{DANGER_RED};'><b>{data.get("threat_flags")}</b></td></tr>
            <tr><td><b>Last Query:</b></td><td style='color:{TEXT_SECONDARY};'>{data.get("timestamp")}</td></tr>
        </table>
        """
        self.details_area.setHtml(html)
