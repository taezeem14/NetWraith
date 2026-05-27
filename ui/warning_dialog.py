"""
NetWraith — Warning Dialog
Full-screen modal legal warning shown at application start.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QGuiApplication

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

WARNING_TEXT = """\
⚠️ LEGAL WARNING — READ BEFORE PROCEEDING

NetWraith is a professional-grade network security analysis tool.

By proceeding, you confirm that:

  • You have EXPLICIT WRITTEN AUTHORIZATION to analyze the target network
  • You are operating in a controlled lab or authorized test environment
  • You are NOT using this tool against any system, network, or service
    without the owner's full legal consent
  • You understand that unauthorized network interception is illegal
    under the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse
    Act, and equivalent laws worldwide

Misuse of this tool may result in criminal prosecution.

The developers assume NO liability for unauthorized or illegal use.\
"""


class WarningDialog(QDialog):
    """Full-screen modal legal warning dialog. Cannot be dismissed without an explicit choice."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Dialog
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setMinimumSize(700, 500)
        self.setModal(True)
        self._setup_ui()
        self._center_on_screen()

    # ── UI Construction ──────────────────────────────────────────────────
    def _setup_ui(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG_DARK};
                border: 2px solid {DANGER_RED};
                border-radius: 12px;
            }}
        """)

        # Red glow effect around the dialog
        glow = QGraphicsDropShadowEffect(self)
        glow.setBlurRadius(40)
        glow.setColor(QColor(DANGER_RED))
        glow.setOffset(0, 0)
        self.setGraphicsEffect(glow)

        root = QVBoxLayout(self)
        root.setContentsMargins(40, 30, 40, 30)
        root.setSpacing(20)

        # ── Warning icon ─────────────────────────────────────────────────
        icon_label = QLabel("⚠️")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFont(QFont("Segoe UI Emoji", 48))
        icon_label.setStyleSheet("background: transparent; border: none;")
        root.addWidget(icon_label)

        # ── Title ────────────────────────────────────────────────────────
        title = QLabel("⚠️ LEGAL WARNING — READ BEFORE PROCEEDING")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont("Segoe UI", 20, QFont.Weight.Bold)
        title.setFont(title_font)
        title.setStyleSheet(f"""
            color: {DANGER_RED};
            background: transparent;
            border: none;
            padding-bottom: 6px;
        """)
        root.addWidget(title)

        # ── Separator ───────────────────────────────────────────────────
        sep = QLabel()
        sep.setFixedHeight(2)
        sep.setStyleSheet(f"background-color: {DANGER_RED}; border: none;")
        root.addWidget(sep)

        # ── Body text ────────────────────────────────────────────────────
        body = QLabel(WARNING_TEXT)
        body.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        body.setWordWrap(True)
        body_font = QFont("Consolas", 12)
        body.setFont(body_font)
        body.setStyleSheet(f"""
            color: {TEXT_PRIMARY};
            background: transparent;
            border: none;
            padding: 10px 4px;
            line-height: 1.5;
        """)
        root.addWidget(body, stretch=1)

        # ── Buttons ──────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(20)

        self.btn_proceed = QPushButton("[ I Understand — Proceed ]")
        self.btn_proceed.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.btn_proceed.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_proceed.setMinimumHeight(48)
        self.btn_proceed.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT_CYAN};
                color: {BG_DARK};
                border: none;
                border-radius: 8px;
                padding: 10px 28px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #33eaff;
            }}
            QPushButton:pressed {{
                background-color: #00bcd4;
            }}
        """)
        self.btn_proceed.clicked.connect(self.accept)

        self.btn_exit = QPushButton("[ Exit ]")
        self.btn_exit.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.btn_exit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_exit.setMinimumHeight(48)
        self.btn_exit.setStyleSheet(f"""
            QPushButton {{
                background-color: {DANGER_RED};
                color: {TEXT_PRIMARY};
                border: none;
                border-radius: 8px;
                padding: 10px 28px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #ff6b6b;
            }}
            QPushButton:pressed {{
                background-color: #e04343;
            }}
        """)
        self.btn_exit.clicked.connect(self.reject)

        btn_row.addStretch()
        btn_row.addWidget(self.btn_proceed)
        btn_row.addWidget(self.btn_exit)
        btn_row.addStretch()
        root.addLayout(btn_row)

    # ── Center on screen ─────────────────────────────────────────────────
    def _center_on_screen(self):
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            x = (geo.width() - self.width()) // 2 + geo.x()
            y = (geo.height() - self.height()) // 2 + geo.y()
            self.move(x, y)

    # ── Prevent closing via X or Escape ──────────────────────────────────
    def closeEvent(self, event):
        event.ignore()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
            return
        super().keyPressEvent(event)
