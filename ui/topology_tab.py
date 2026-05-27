"""
NetWraith — Topology Tab
========================
Custom interactive 2D node map showing live hosts and their relationships.
Nodes are drag-and-drop movable. Double-clicking any host node opens it in the Ports Tab.
"""

import math
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QGraphicsView, QGraphicsScene, QGraphicsItem,
    QGraphicsEllipseItem, QGraphicsLineItem, QLabel, QHBoxLayout, QFrame,
    QGraphicsSimpleTextItem
)
from PyQt6.QtCore import Qt, QPointF
from PyQt6.QtGui import QColor, QFont, QPen, QBrush, QPainter

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

class TopologyNode(QGraphicsEllipseItem):
    """Interactive circular device node on the topology canvas."""

    def __init__(self, ip: str, mac: str, vendor: str, os_guess: str, status: str, is_gateway: bool = False, double_click_callback=None):
        super().__init__(-22, -22, 44, 44)
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.os_guess = os_guess
        self.status = status
        self.is_gateway = is_gateway
        self.double_click_callback = double_click_callback

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)

        # Style colors
        if is_gateway:
            self.setBrush(QBrush(QColor("#1e1430")))  # Deep purple background
            self.setPen(QPen(QColor("#bb86fc"), 3))    # Purple glow border
        else:
            status_colors = {
                "TRUSTED": SUCCESS_GREEN,
                "NEW": ACCENT_CYAN,
                "CHANGED": WARNING_AMBER,
                "SUSPICIOUS": DANGER_RED
            }
            color = status_colors.get(status.upper(), TEXT_SECONDARY)
            self.setBrush(QBrush(QColor(BG_PANEL)))
            self.setPen(QPen(QColor(color), 2))

        # Add IP address label inside or under the node
        self.text_item = QGraphicsSimpleTextItem(self.ip, self)
        self.text_item.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        self.text_item.setBrush(QBrush(QColor(TEXT_PRIMARY)))
        
        # Center the text below the node
        text_w = self.text_item.boundingRect().width()
        self.text_item.setPos(-text_w / 2, 28)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemFlag.ItemPositionHasChanged:
            scene = self.scene()
            if scene and hasattr(scene, "draw_lines"):
                scene.draw_lines()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        role = "🌐 DEFAULT GATEWAY (Router)" if self.is_gateway else "🖥️ SUBNET HOST"
        tooltip = (
            f"{role}\n"
            f"───────────────────\n"
            f"IP: {self.ip}\n"
            f"MAC: {self.mac}\n"
            f"Vendor: {self.vendor}\n"
            f"OS Fingerprint: {self.os_guess}\n"
            f"Status: {self.status}"
        )
        self.setToolTip(tooltip)
        super().hoverEnterEvent(event)

    def mouseDoubleClickEvent(self, event):
        if self.double_click_callback and not self.is_gateway:
            self.double_click_callback(self.ip)
        super().mouseDoubleClickEvent(event)


class TopologyScene(QGraphicsScene):
    """GraphicsScene hosting the nodes and connecting link lines."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes = []
        self.lines = []
        self.gateway_node = None

    def draw_lines(self):
        for line, node in self.lines:
            if self.gateway_node and node:
                line.setLine(
                    self.gateway_node.scenePos().x(), self.gateway_node.scenePos().y(),
                    node.scenePos().x(), node.scenePos().y()
                )


class TopologyTab(QWidget):
    """Network Topology Mapping workspace Tab."""

    def __init__(self, parent=None, double_click_callback=None):
        super().__init__(parent)
        self.double_click_callback = double_click_callback
        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        # Header info
        info_bar = QHBoxLayout()
        info_label = QLabel("🕸️ Live Network Topology Map")
        info_label.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        info_label.setStyleSheet(f"color: {ACCENT_CYAN};")
        info_bar.addWidget(info_label)
        
        legend = QLabel("Legend: 🟣 Gateway | 🟢 Trusted | 🔵 New | 🟡 MAC Shift | 🔴 Suspicious")
        legend.setFont(QFont("Segoe UI", 10))
        legend.setStyleSheet(f"color: {TEXT_SECONDARY};")
        info_bar.addWidget(legend, alignment=Qt.AlignmentFlag.AlignRight)
        
        lay.addLayout(info_bar)

        # Workspace viewport
        self.scene = TopologyScene(self)
        self.scene.setBackgroundBrush(QBrush(QColor(BG_DARK)))
        self.scene.setSceneRect(-300, -300, 600, 600)

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setStyleSheet(f"""
            QGraphicsView {{
                border: 1px solid {BORDER_COLOR};
                background-color: {BG_DARK};
                border-radius: 8px;
            }}
        """)
        self.view.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        lay.addWidget(self.view)

        # Bottom label
        self.lbl_summary = QLabel("Run a hosts ARP scan to populate the topology layout.")
        self.lbl_summary.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; padding: 2px;")
        lay.addWidget(self.lbl_summary)

    def update_nodes(self, hosts: list[dict], gateway_ip: str):
        """Redraw nodes in a circular layout connected to the gateway."""
        self.scene.clear()
        self.scene.nodes.clear()
        self.scene.lines.clear()
        self.scene.gateway_node = None

        if not gateway_ip:
            self.lbl_summary.setText("No gateway detected. Cannot build topology.")
            return

        # Gateway details from hosts
        gw_mac = "Unknown"
        gw_vendor = "Unknown"
        gw_os = "Unknown"
        for h in hosts:
            if h.get("ip") == gateway_ip:
                gw_mac = h.get("mac", "Unknown")
                gw_vendor = h.get("vendor", "Unknown")
                gw_os = h.get("os_guess", "Unknown")
                break

        # Center Node: Router / Gateway
        self.scene.gateway_node = TopologyNode(
            gateway_ip, gw_mac, gw_vendor, gw_os, "TRUSTED", is_gateway=True
        )
        self.scene.gateway_node.setPos(0, 0)
        self.scene.addItem(self.scene.gateway_node)

        # Other satellite host nodes
        satellites = [h for h in hosts if h.get("ip") != gateway_ip]
        count = len(satellites)
        radius = 160.0

        for i, h in enumerate(satellites):
            angle = (2 * math.pi * i) / count if count > 0 else 0
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)

            node = TopologyNode(
                h.get("ip", ""),
                h.get("mac", ""),
                h.get("vendor", "Unknown"),
                h.get("os_guess", "Unknown"),
                h.get("status", "NEW"),
                is_gateway=False,
                double_click_callback=self.double_click_callback
            )
            node.setPos(x, y)

            # Link line to center gateway
            pen = QPen(QColor(BORDER_COLOR), 1, Qt.PenStyle.DashLine)
            line = QGraphicsLineItem(0, 0, x, y)
            line.setPen(pen)

            # Draw line behind the node
            self.scene.addItem(line)
            self.scene.addItem(node)

            self.scene.nodes.append(node)
            self.scene.lines.append((line, node))

        # Position connections
        self.scene.draw_lines()
        self.lbl_summary.setText(f"Mapped {count} network nodes linked to gateway {gateway_ip}. Double-click host to scan ports.")
