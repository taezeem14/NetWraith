"""
NetWraith — Network Security Analyzer
===========================================

Entry point for the application.  Applies the global dark theme stylesheet,
shows the legal‑warning dialog, and launches the main window.
"""

import sys
import os

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import Qt

# ---------------------------------------------------------------------------
# Theme constants (single source of truth for the whole app)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Global stylesheet applied to every widget in the application
# ---------------------------------------------------------------------------
GLOBAL_STYLESHEET = f"""
/* ---- base ---- */
QWidget {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    font-family: "Segoe UI", "Consolas", "Courier New", monospace;
    font-size: 13px;
}}

/* ---- menus ---- */
QMenuBar {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border-bottom: 1px solid {BORDER_COLOR};
    padding: 2px 0px;
}}
QMenuBar::item:selected {{
    background-color: {ACCENT_CYAN};
    color: {BG_DARK};
    border-radius: 4px;
}}
QMenu {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    padding: 4px;
}}
QMenu::item:selected {{
    background-color: {ACCENT_CYAN};
    color: {BG_DARK};
}}
QMenu::separator {{
    height: 1px;
    background: {BORDER_COLOR};
    margin: 4px 8px;
}}

/* ---- tooltips ---- */
QToolTip {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {ACCENT_CYAN};
    padding: 4px 8px;
    border-radius: 4px;
}}

/* ---- scroll bars ---- */
QScrollBar:vertical {{
    background: {BG_DARK};
    width: 10px;
    margin: 0;
    border-radius: 5px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER_COLOR};
    min-height: 30px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT_CYAN};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {BG_DARK};
    height: 10px;
    margin: 0;
    border-radius: 5px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER_COLOR};
    min-width: 30px;
    border-radius: 5px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {ACCENT_CYAN};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ---- tables ---- */
QTableWidget, QTableView {{
    background-color: {BG_PANEL};
    alternate-background-color: {BG_DARK};
    gridline-color: {BORDER_COLOR};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    selection-background-color: rgba(0, 229, 255, 0.18);
    selection-color: {ACCENT_CYAN};
}}
QHeaderView::section {{
    background-color: {BG_DARK};
    color: {ACCENT_CYAN};
    padding: 6px;
    border: none;
    border-bottom: 2px solid {ACCENT_CYAN};
    font-weight: bold;
}}

/* ---- inputs ---- */
QLineEdit, QSpinBox, QDoubleSpinBox {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {ACCENT_CYAN};
    selection-color: {BG_DARK};
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 1px solid {ACCENT_CYAN};
}}

/* ---- combo boxes ---- */
QComboBox {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px 10px;
    min-width: 180px;
}}
QComboBox:hover {{
    border-color: {ACCENT_CYAN};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    selection-background-color: {ACCENT_CYAN};
    selection-color: {BG_DARK};
}}

/* ---- push buttons (generic) ---- */
QPushButton {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 7px 18px;
    font-weight: bold;
}}
QPushButton:hover {{
    border-color: {ACCENT_CYAN};
    color: {ACCENT_CYAN};
}}
QPushButton:pressed {{
    background-color: {ACCENT_CYAN};
    color: {BG_DARK};
}}

/* ---- check boxes ---- */
QCheckBox {{
    spacing: 8px;
    color: {TEXT_PRIMARY};
}}
QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {BORDER_COLOR};
    border-radius: 4px;
    background-color: {BG_DARK};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT_CYAN};
    border-color: {ACCENT_CYAN};
}}

/* ---- group boxes ---- */
QGroupBox {{
    border: 1px solid {BORDER_COLOR};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 14px;
    color: {TEXT_PRIMARY};
    font-weight: bold;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
}}

/* ---- tab widget (fallback) ---- */
QTabWidget::pane {{
    border: 1px solid {BORDER_COLOR};
    background-color: {BG_PANEL};
    border-radius: 6px;
}}
QTabBar::tab {{
    background-color: {BG_DARK};
    color: {TEXT_SECONDARY};
    padding: 8px 16px;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{
    color: {ACCENT_CYAN};
    border-bottom: 2px solid {ACCENT_CYAN};
}}

/* ---- status bar ---- */
QStatusBar {{
    background-color: {BG_PANEL};
    color: {TEXT_SECONDARY};
    border-top: 1px solid {BORDER_COLOR};
    font-size: 12px;
}}
QStatusBar::item {{
    border: none;
}}

/* ---- progress bars ---- */
QProgressBar {{
    background-color: {BG_DARK};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    text-align: center;
    color: {TEXT_PRIMARY};
    height: 18px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT_CYAN};
    border-radius: 5px;
}}

/* ---- dialogs ---- */
QDialog {{
    background-color: {BG_DARK};
}}

/* ---- labels ---- */
QLabel {{
    background-color: transparent;
    color: {TEXT_PRIMARY};
}}

/* ---- text edits ---- */
QTextEdit, QPlainTextEdit {{
    background-color: {BG_DARK};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_COLOR};
    border-radius: 6px;
    padding: 6px;
    selection-background-color: {ACCENT_CYAN};
    selection-color: {BG_DARK};
}}

/* ---- splitter ---- */
QSplitter::handle {{
    background-color: {BORDER_COLOR};
}}
"""


def main() -> None:
    """Launch the NetWraith application."""
    # Print clean text header
    print("==================================================")
    print("                 🕸️  NetWraith                    ")
    print("==================================================")
    print("  Author: Muhammad Taezeem Tariq Matta")
    print("  Telegram: t.me/Taezeem_14")
    print("  GitHub: github.com/taezeem14")
    print("==================================================")

    # High-DPI support (Qt6 enables it by default, but be explicit)
    app = QApplication(sys.argv)
    app.setApplicationName("NetWraith")
    app.setOrganizationName("NetWraith")


    # ---- Application icon (graceful fallback if missing) ----
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.png")
    if os.path.isfile(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # ---- Global font ----
    font = QFont("Segoe UI", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)

    # ---- Global stylesheet ----
    app.setStyleSheet(GLOBAL_STYLESHEET)

    # ---- Legal warning dialog (must accept to proceed) ----
    from ui.warning_dialog import WarningDialog  # noqa: late import keeps startup fast

    warning = WarningDialog()
    if warning.exec() != WarningDialog.DialogCode.Accepted:
        sys.exit(0)

    # ---- Main window ----
    from ui.main_window import MainWindow  # noqa

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
