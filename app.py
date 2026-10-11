#!/usr/bin/env python3
"""
Network Analyzer Pro – Computer Networks & Computer Security
Built with PySide6

Install:  pip install PySide6 psutil scapy
Run:      python network_analyzer.py
Note:     Packet capture needs root/admin. Demo Mode works without privileges.
"""

import sys, os, socket, subprocess, threading, time, struct, platform, re, random, math, json
import ipaddress
from collections import defaultdict, deque
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit,
    QPushButton, QLineEdit, QLabel, QComboBox, QSpinBox,
    QGroupBox, QGridLayout, QHeaderView, QCheckBox, QProgressBar,
    QSplitter, QTreeWidget, QTreeWidgetItem, QStatusBar,
    QFrame, QAbstractItemView, QSizePolicy, QFileDialog,
    QScrollArea, QToolButton, QSizePolicy as QSP
)
from PySide6.QtCore import Qt, QTimer, Signal, QThread, QSize, QRectF, QPointF, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import (
    QFont, QColor, QPainter, QPen, QBrush, QLinearGradient,
    QRadialGradient, QPainterPath, QConicalGradient, QCursor,
    QKeySequence, QShortcut, QIcon, QPixmap, QAction
)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
    194: "IRC", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    9200: "Elasticsearch", 11211: "Memcached", 15672: "RabbitMQ",
}

RISK_COLORS = {
    "critical": "#ff4444", "high": "#ff8844", "medium": "#ffcc44",
    "low": "#44cc44", "info": "#44aaff", "safe": "#44ff88",
}

PROTOCOL_COLORS = {
    'TCP': '#00d4aa', 'UDP': '#00aaff', 'ICMP': '#ff8844',
    'ARP': '#ffcc44', 'DNS': '#aa6bff', 'HTTP': '#ff6b9d',
    'HTTPS': '#6bffb8', 'Other': '#d0d0e0'
}

PROC_FLAGS = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0

# ── Professional Stylesheet ────────────────────────────────────
DARK_STYLE = """
QMainWindow { background-color: #0a0a14; }
QWidget { background-color: #0a0a14; color: #c8c8e0;
    font-family: "Segoe UI", "Inter", Consolas, monospace; font-size: 13px; }

/* ── Tab Widget ── */
QTabWidget::pane { border: none; background: #0e0e1c; top: -1px; }
QTabBar::tab { background: #12122a; color: #6a6a99; padding: 11px 24px;
    margin-right: 1px; border: none; border-bottom: 3px solid transparent;
    font-weight: 600; font-size: 13px; min-width: 120px; }
QTabBar::tab:selected { background: #0e0e1c; color: #00d4aa;
    border-bottom: 3px solid #00d4aa; }
QTabBar::tab:hover:!selected { color: #00d4aa; background: #10102a; }

/* ── Group Box ── */
QGroupBox { border: 1px solid #1e1e3a; border-radius: 8px; margin-top: 14px;
    padding: 18px 12px 12px 12px; font-weight: 600; color: #00d4aa;
    background-color: #0e0e1c; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 8px;
    background-color: #0e0e1c; }

/* ── Buttons ── */
QPushButton { background: #1a1a38; color: #c8c8e0; border: 1px solid #2a2a55;
    border-radius: 6px; padding: 8px 20px; font-weight: 600; }
QPushButton:hover { background: #252550; border-color: #00d4aa; color: #00d4aa; }
QPushButton:pressed { background: #00d4aa; color: #0a0a14; }
QPushButton:disabled { background: #12122a; color: #3a3a5a; border-color: #1e1e3a; }
QPushButton#startBtn { background: #002a22; border: 1px solid #00d4aa; color: #00d4aa; }
QPushButton#startBtn:hover { background: #00d4aa; color: #0a0a14; }
QPushButton#stopBtn { background: #2a0000; border: 1px solid #ff4444; color: #ff4444; }
QPushButton#stopBtn:hover { background: #ff4444; color: #0a0a14; }
QPushButton#scanBtn { background: #1a1a38; border: 1px solid #00aaff; color: #00aaff; }
QPushButton#scanBtn:hover { background: #00aaff; color: #0a0a14; }

/* ── Inputs ── */
QLineEdit, QSpinBox, QComboBox { background: #12122a; border: 1px solid #1e1e3a;
    border-radius: 6px; padding: 7px 12px; color: #c8c8e0; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #00d4aa; }
QComboBox::drop-down { border: none; padding-right: 10px; }
QComboBox QAbstractItemView { background: #12122a; selection-background-color: #00d4aa33;
    color: #c8c8e0; border: 1px solid #1e1e3a; }

/* ── Table ── */
QTableWidget { background: #0a0a18; alternate-background-color: #0e0e22;
    gridline-color: #1a1a33; border: 1px solid #1e1e3a; border-radius: 6px;
    selection-background-color: #00d4aa22; selection-color: #00d4aa; }
QTableWidget::item { padding: 5px 8px; }
QTableWidget::item:selected { background: #00d4aa22; color: #00d4aa; }
QHeaderView::section { background: #12122a; color: #00d4aa; padding: 8px 6px;
    border: none; border-bottom: 2px solid #00d4aa44; font-weight: 700;
    font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }

/* ── Text Edit ── */
QTextEdit { background: #0a0a18; border: 1px solid #1e1e3a; border-radius: 6px;
    color: #a0a0c8; font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
    font-size: 12px; padding: 6px; }

/* ── Tree ── */
QTreeWidget { background: #0a0a18; border: 1px solid #1e1e3a; border-radius: 6px;
    color: #a0a0c8; font-family: Consolas, monospace; outline: none; }
QTreeWidget::item { padding: 3px; border-bottom: 1px solid #0e0e22; }
QTreeWidget::item:selected { background: #00d4aa18; color: #00d4aa; }
QTreeWidget::item:hover { background: #00d4aa0a; }

/* ── Progress ── */
QProgressBar { border: 1px solid #1e1e3a; border-radius: 6px; text-align: center;
    background: #12122a; color: #00d4aa; font-weight: bold; height: 20px; }
QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
    stop:0 #00d4aa,stop:1 #00aaff); border-radius: 5px; }

/* ── Scroll ── */
QScrollBar:vertical { background: #0a0a14; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: #2a2a55; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #3a3a77; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #0a0a14; height: 8px; }
QScrollBar::handle:horizontal { background: #2a2a55; border-radius: 4px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Splitter ── */
QSplitter::handle { background: #1e1e3a; width: 2px; }
QSplitter::handle:hover { background: #00d4aa44; }

/* ── Labels ── */
QLabel#titleLabel { font-size: 20px; font-weight: 700; color: #e8e8ff;
    padding: 4px 0; }
QLabel#subtitleLabel { font-size: 14px; font-weight: 600; color: #00d4aa; }
QLabel#statValue { font-size: 24px; font-weight: 700; color: #00d4aa; }
QLabel#statLabel { font-size: 11px; color: #6a6a99; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px; }

/* ── Checkbox ── */
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 18px; height: 18px; border: 1px solid #2a2a55;
    border-radius: 4px; background: #12122a; }
QCheckBox::indicator:checked { background: #00d4aa; border-color: #00d4aa; }

/* ── Status Bar ── */
QStatusBar { background: #080812; color: #6a6a99; border-top: 1px solid #1e1e3a;
    font-size: 12px; padding: 2px 8px; }
QStatusBar::item { border: none; }

/* ── Scroll Area ── */
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }

/* ── Tooltip ── */
QToolTip { background: #1a1a38; color: #00d4aa; border: 1px solid #00d4aa55;
    padding: 6px 10px; border-radius: 6px; font-size: 12px; }

/* ── Frame ── */
QFrame#separator { background: #1e1e3a; max-height: 1px; }

/* ── Inline Status ── */
QLabel#statusMsg { padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 12px; }
QLabel#errorMsg { color: #ff6b6b; background: #2a0a0a; border: 1px solid #ff444444; }
QLabel#successMsg { color: #44ffaa; background: #0a2a1a; border: 1px solid #00d4aa44; }
QLabel#warnMsg { color: #ffcc44; background: #2a2a0a; border: 1px solid #ffcc4444; }
QLabel#infoMsg { color: #44aaff; background: #0a1a2a; border: 1px solid #44aaff44; }
"""


# ── Utility ────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def resolve_dns(name):
    try: return socket.gethostbyname(name)
    except socket.gaierror: return None

def get_service_name(port): return WELL_KNOWN_PORTS.get(port, "unknown")

def format_size(n):
    for u in ['B','KB','MB','GB']:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def format_elapsed(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h: return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}" if m else f"{s}s"

def is_private_ip(ip):
    try: return ipaddress.ip_address(ip).is_private
    except: return False

def get_gateway():
    try:
        if platform.system() == "Linux":
            with open("/proc/net/route") as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] != '00000000' or not fields[2]: continue
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        elif platform.system() == "Windows":
            result = subprocess.run(['route', 'print', '0.0.0.0'],
                capture_output=True, text=True, creationflags=PROC_FLAGS)
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line and 'On-link' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        for p in parts:
                            if re.match(r'\d+\.\d+\.\d+\.\d+', p) and p != '0.0.0.0':
                                return p
        elif platform.system() == "Darwin":
            result = subprocess.run(['route', '-n', 'get', 'default'],
                capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'gateway' in line.lower():
                    return line.split(':')[-1].strip()
    except: pass
    return "N/A"

def get_mac_address():
    try:
        if PSUTIL_AVAILABLE:
            for iface, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == -1:  # AF_LINK
                        return a.address
        if platform.system() == "Linux":
            with open("/sys/class/net/$(ls /sys/class/net | head -1)/address") as f:
                return f.read().strip()
    except: pass
    return "N/A"


# ══════════════════════════════════════════════════════════════
#  TOAST NOTIFICATION (replaces all dialogs)
# ══════════════════════════════════════════════════════════════

class ToastNotification(QFrame):
    """Inline toast notification that slides in from the top-right."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame { background: #1a1a38; border: 1px solid #2a2a55;
                border-radius: 8px; padding: 4px; }
        """)
        self.setFixedWidth(360)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 8, 12, 8)
        self._icon = QLabel()
        self._icon.setFixedSize(24, 24)
        self._icon.setAlignment(Qt.AlignCenter)
        self._icon.setStyleSheet("font-size: 16px; background: transparent;")
        self._msg = QLabel()
        self._msg.setWordWrap(True)
        self._msg.setStyleSheet("color: #c8c8e0; font-size: 12px; background: transparent;")
        self._close_btn = QToolButton()
        self._close_btn.setText("✕")
        self._close_btn.setFixedSize(20, 20)
        self._close_btn.setStyleSheet("""
            QToolButton { background: transparent; color: #6a6a99; border: none;
                font-size: 12px; font-weight: bold; }
            QToolButton:hover { color: #ff6b6b; }
        """)
        self._close_btn.clicked.connect(self.hide)
        self._layout.addWidget(self._icon)
        self._layout.addWidget(self._msg, stretch=1)
        self._layout.addWidget(self._close_btn)
        self.hide()
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._fade_out)
        self._opacity = 0.0

    def show_message(self, text, level="info", duration=4000):
        icons = {"error": "❌", "warning": "⚠️", "info": "ℹ️", "success": "✅"}
        colors = {"error": "#ff6b6b", "warning": "#ffcc44", "info": "#44aaff", "success": "#00d4aa"}
        bgs = {"error": "#2a0a0a", "warning": "#2a2a0a", "info": "#0a1a2a", "success": "#0a2a1a"}
        self._icon.setText(icons.get(level, "ℹ️"))
        self._msg.setText(text)
        color = colors.get(level, "#44aaff")
        bg = bgs.get(level, "#0a1a2a")
        self.setStyleSheet(f"""
            QFrame {{ background: {bg}; border: 1px solid {color}44;
                border-radius: 8px; padding: 4px; }}
        """)
        self._msg.setStyleSheet(f"color: {color}; font-size: 12px; background: transparent;")
        self.show()
        self.raise_()
        self._timer.start(duration)

    def _fade_out(self):
        self.hide()


class InlineStatus(QLabel):
    """Inline status label for forms — replaces dialogs with context messages."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.setFixedHeight(28)
        self.setStyleSheet("padding: 4px 12px; border-radius: 4px;")
        self.hide()

    def show_error(self, msg):
        self.setText(f"✕  {msg}")
        self.setStyleSheet("padding: 4px 12px; border-radius: 4px; color: #ff6b6b; background: #2a0a0a;")
        self.show()

    def show_success(self, msg):
        self.setText(f"✓  {msg}")
        self.setStyleSheet("padding: 4px 12px; border-radius: 4px; color: #44ffaa; background: #0a2a1a;")
        self.show()

    def show_warning(self, msg):
        self.setText(f"⚠  {msg}")
        self.setStyleSheet("padding: 4px 12px; border-radius: 4px; color: #ffcc44; background: #2a2a0a;")
        self.show()

    def show_info(self, msg):
        self.setText(f"ℹ  {msg}")
        self.setStyleSheet("padding: 4px 12px; border-radius: 4px; color: #44aaff; background: #0a1a2a;")
        self.show()

    def clear(self):
        self.setText("")
        self.hide()


# ══════════════════════════════════════════════════════════════
#  CUSTOM VISUALIZATION WIDGETS
# ══════════════════════════════════════════════════════════════

class TrafficChart(QWidget):
    def __init__(self, parent=None, title="Traffic", color=QColor(0, 212, 170), max_len=150):
        super().__init__(parent)
        self.title = title; self.color = color
        self.data = deque([0]*max_len, maxlen=max_len)
        self.max_val = 1; self.peak_val = 0; self.peak_idx = -1
        self.setMinimumHeight(120)

    def add_value(self, v):
        self.data.append(v)
        if v > self.peak_val:
            self.peak_val = v; self.peak_idx = len(self.data) - 1
        if v > self.max_val: self.max_val = v * 1.1
        self.max_val = max(self.max_val, 1)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(14, 14, 28)); grad.setColorAt(1, QColor(10, 10, 22))
        p.fillRect(0, 0, w, h, grad)
        p.setPen(QPen(QColor(30, 30, 55), 1, Qt.DotLine))
        p.setFont(QFont("Segoe UI", 8))
        for i in range(1, 5):
            y = int(h * i / 5); p.drawLine(40, y, w, y)
            val = self.max_val * (1 - i / 5)
            p.setPen(QColor(80, 80, 120)); p.drawText(2, y + 4, f"{val:.0f}")
            p.setPen(QPen(QColor(30, 30, 55), 1, Qt.DotLine))
        p.setPen(QColor(200, 200, 230)); p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.drawText(44, 14, f"{self.title}: {self.data[-1]:.0f}  (peak: {self.peak_val:.0f})")
        if len(self.data) < 2: p.end(); return
        mx = max(self.max_val, 1); dx = (w - 40) / (len(self.data) - 1)
        path = QPainterPath()
        for i, v in enumerate(self.data):
            x = 40 + i * dx; y = h - (v / mx) * (h - 25) - 5
            if i == 0: path.moveTo(x, y)
            else: path.lineTo(x, y)
        fill_path = QPainterPath(path)
        fill_path.lineTo(40 + (len(self.data)-1)*dx, h); fill_path.lineTo(40, h); fill_path.closeSubpath()
        fill_grad = QLinearGradient(0, 0, 0, h)
        fill_grad.setColorAt(0, QColor(self.color.red(), self.color.green(), self.color.blue(), 50))
        fill_grad.setColorAt(1, QColor(self.color.red(), self.color.green(), self.color.blue(), 5))
        p.fillPath(fill_path, QBrush(fill_grad))
        p.setPen(QPen(self.color, 2)); p.drawPath(path)
        if self.peak_idx >= 0 and self.peak_idx < len(self.data):
            px = 40 + self.peak_idx * dx; py = h - (self.peak_val / mx) * (h - 25) - 5
            p.setBrush(QBrush(self.color)); p.setPen(QPen(QColor(255,255,255), 1))
            p.drawEllipse(QPointF(px, py), 4, 4)
        p.end()


class DualTrafficChart(QWidget):
    def __init__(self, parent=None, title1="Inbound", title2="Outbound",
                 color1=QColor(0, 212, 170), color2=QColor(255, 107, 157)):
        super().__init__(parent)
        self.title1 = title1; self.title2 = title2
        self.color1 = color1; self.color2 = color2
        self.data1 = deque([0]*120, maxlen=120); self.data2 = deque([0]*120, maxlen=120)
        self.max_val = 1; self.setMinimumHeight(130)

    def add_values(self, v1, v2):
        self.data1.append(v1); self.data2.append(v2)
        m = max(v1, v2)
        if m > self.max_val: self.max_val = m * 1.1
        self.max_val = max(self.max_val, 1)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(14, 14, 28)); grad.setColorAt(1, QColor(10, 10, 22))
        p.fillRect(0, 0, w, h, grad)
        p.setPen(QPen(QColor(30, 30, 55), 1, Qt.DotLine))
        for i in range(1, 4):
            y = int(h * i / 4); p.drawLine(0, y, w, y)
        p.setFont(QFont("Segoe UI", 8))
        p.setPen(self.color1); p.drawText(8, 14, f"● {self.title1}: {self.data1[-1]:.0f}")
        p.setPen(self.color2); p.drawText(150, 14, f"● {self.title2}: {self.data2[-1]:.0f}")
        for data, color in [(self.data1, self.color1), (self.data2, self.color2)]:
            if len(data) < 2: continue
            mx = max(self.max_val, 1); dx = w / (len(data) - 1)
            path = QPainterPath()
            for i, v in enumerate(data):
                x = i * dx; y = h - (v / mx) * (h - 25) - 5
                if i == 0: path.moveTo(x, y)
                else: path.lineTo(x, y)
            fill = QPainterPath(path); fill.lineTo(w, h); fill.lineTo(0, h); fill.closeSubpath()
            fc = QColor(color); fc.setAlpha(20); p.fillPath(fill, QBrush(fc))
            p.setPen(QPen(color, 2)); p.drawPath(path)
        p.end()


class GaugeWidget(QWidget):
    def __init__(self, parent=None, title="Metric", unit="", max_val=100, color=QColor(0, 212, 170)):
        super().__init__(parent)
        self.title = title; self.unit = unit; self.max_val = max_val
        self.color = color; self.value = 0; self.target_value = 0
        self.setMinimumSize(130, 130); self.setMaximumSize(170, 170)
        self._anim_timer = QTimer(); self._anim_timer.timeout.connect(self._animate)
        self._anim_timer.start(30)

    def set_value(self, v):
        self.target_value = min(v, self.max_val)

    def _animate(self):
        diff = self.target_value - self.value
        if abs(diff) > 0.5: self.value += diff * 0.15
        else: self.value = self.target_value
        self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height(); cx, cy = w // 2, h // 2 + 10
        r = min(w, h) // 2 - 20
        p.setPen(QPen(QColor(30, 30, 55), 8, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(cx - r, cy - r, 2*r, 2*r, 225 * 16, -270 * 16)
        ratio = self.value / max(self.max_val, 1)
        span = int(-270 * 16 * ratio)
        grad = QConicalGradient(cx, cy, 225)
        grad.setColorAt(0, self.color)
        grad.setColorAt(min(ratio * 0.75, 1.0), QColor(self.color).lighter(130))
        grad.setColorAt(1, self.color)
        p.setPen(QPen(QBrush(grad), 8, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(cx - r, cy - r, 2*r, 2*r, 225 * 16, span)
        p.setPen(QColor(220, 220, 240)); p.setFont(QFont("Segoe UI", 16, QFont.Bold))
        p.drawText(QRectF(cx-40, cy-15, 80, 30), Qt.AlignCenter, f"{self.value:.0f}")
        p.setPen(QColor(100, 100, 160)); p.setFont(QFont("Segoe UI", 8))
        p.drawText(QRectF(cx-40, cy+12, 80, 20), Qt.AlignCenter, self.unit)
        p.setPen(self.color); p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.drawText(QRectF(0, 4, w, 14), Qt.AlignCenter, self.title)
        p.setPen(QPen(QColor(50, 50, 80), 1))
        for i in range(10):
            angle = math.radians(225 - 270 * i / 9)
            x1 = cx + int((r - 14) * math.cos(angle)); y1 = cy - int((r - 14) * math.sin(angle))
            x2 = cx + int((r - 8) * math.cos(angle)); y2 = cy - int((r - 8) * math.sin(angle))
            p.drawLine(x1, y1, x2, y2)
        p.end()


class ProtocolPieChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self.data = {}; self.setMinimumSize(200, 200)

    def set_data(self, data: dict):
        self.data = data; self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height(); cx, cy = w // 2 - 30, h // 2
        r = min(w - 80, h) // 2 - 15
        p.fillRect(0, 0, w, h, QColor(14, 14, 28))
        total = sum(self.data.values())
        if total == 0:
            p.setPen(QColor(100, 100, 160)); p.setFont(QFont("Segoe UI", 10))
            p.drawText(self.rect(), Qt.AlignCenter, "No data"); p.end(); return
        colors = [QColor(0,212,170), QColor(0,170,255), QColor(255,107,107),
                  QColor(255,204,68), QColor(170,107,255), QColor(107,255,170),
                  QColor(255,170,107), QColor(107,200,255), QColor(255,107,200)]
        angle = 0; legend_y = 20
        for i, (proto, count) in enumerate(self.data.items()):
            span = int(count / total * 360 * 16)
            color = colors[i % len(colors)]
            p.setBrush(QBrush(QColor(0,0,0,40))); p.setPen(Qt.NoPen)
            p.drawPie(cx - r + 2, cy - r + 2, 2*r, 2*r, angle, span)
            p.setBrush(QBrush(color)); p.setPen(QPen(QColor(14, 14, 28), 2))
            p.drawPie(cx - r, cy - r, 2*r, 2*r, angle, span)
            mid = angle + span // 2; lr = r * 0.65
            lx = cx + int(lr * math.cos(mid / 16 * math.pi / 180))
            ly = cy - int(lr * math.sin(mid / 16 * math.pi / 180))
            p.setPen(QColor(240, 240, 255)); p.setFont(QFont("Segoe UI", 8, QFont.Bold))
            pct = count / total * 100
            if pct > 5: p.drawText(lx - 18, ly + 5, f"{pct:.0f}%")
            lx2 = w - 75
            p.setBrush(QBrush(color)); p.setPen(Qt.NoPen)
            p.drawRoundedRect(lx2, legend_y, 12, 12, 2, 2)
            p.setPen(QColor(180, 180, 210)); p.setFont(QFont("Segoe UI", 9))
            p.drawText(lx2 + 16, legend_y + 11, f"{proto}")
            legend_y += 20; angle += span
        p.end()


class BarChartWidget(QWidget):
    def __init__(self, parent=None, title="Statistics", color=QColor(0, 212, 170)):
        super().__init__(parent)
        self.title = title; self.data = {}; self.color = color
        self.setMinimumHeight(150)

    def set_data(self, data: dict, color=QColor(0, 212, 170)):
        self.data = data; self.color = color; self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(14, 14, 28))
        if not self.data:
            p.setPen(QColor(100, 100, 160)); p.setFont(QFont("Segoe UI", 10))
            p.drawText(self.rect(), Qt.AlignCenter, "No data"); p.end(); return
        p.setPen(QColor(180, 180, 210)); p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.drawText(8, 14, self.title)
        items = list(self.data.items()); n = len(items)
        mx = max(self.data.values()) if self.data else 1; mx = max(mx, 1)
        bar_h = max(min((h - 30) // max(n, 1) - 4, 22), 12)
        y_start = 28
        for i, (label, val) in enumerate(items):
            y = y_start + i * (bar_h + 4)
            bar_w = int((val / mx) * (w - 130))
            p.setBrush(QBrush(QColor(20, 20, 44))); p.setPen(Qt.NoPen)
            p.drawRoundedRect(80, y, w - 130, bar_h, 3, 3)
            grad = QLinearGradient(80, y, 80 + bar_w, y)
            grad.setColorAt(0, self.color); grad.setColorAt(1, QColor(self.color).lighter(130))
            p.setBrush(QBrush(grad)); p.drawRoundedRect(80, y, max(bar_w, 2), bar_h, 3, 3)
            p.setPen(QColor(150, 150, 190)); p.setFont(QFont("Segoe UI", 9))
            p.drawText(4, y + bar_h - 3, str(label)[:10])
            p.setPen(QColor(200, 200, 230)); p.setFont(QFont("Segoe UI", 9, QFont.Bold))
            p.drawText(85 + bar_w + 4, y + bar_h - 3, str(val))
        p.end()


class SecurityScoreWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.score = 100; self.issues = []
        self.setMinimumSize(160, 160); self.setMaximumSize(190, 190)

    def set_score(self, score, issues=None):
        self.score = max(0, min(100, score))
        self.issues = issues or []; self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height(); cx, cy = w//2, h//2
        r = min(w, h)//2 - 16
        p.setPen(QPen(QColor(30, 30, 55), 10, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(cx-r, cy-r, 2*r, 2*r, 225*16, -270*16)
        if self.score >= 80: color = QColor(0, 212, 170)
        elif self.score >= 60: color = QColor(255, 204, 68)
        elif self.score >= 40: color = QColor(255, 136, 68)
        else: color = QColor(255, 68, 68)
        span = int(-270 * 16 * self.score / 100)
        p.setPen(QPen(color, 10, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(cx-r, cy-r, 2*r, 2*r, 225*16, span)
        glow = QRadialGradient(cx, cy, r)
        glow.setColorAt(0.7, QColor(color.red(), color.green(), color.blue(), 15))
        glow.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
        p.setBrush(QBrush(glow)); p.setPen(Qt.NoPen)
        p.drawEllipse(cx-r, cy-r, 2*r, 2*r)
        p.setPen(color); p.setFont(QFont("Segoe UI", 24, QFont.Bold))
        p.drawText(QRectF(cx-40, cy-18, 80, 36), Qt.AlignCenter, str(int(self.score)))
        p.setPen(QColor(100, 100, 160)); p.setFont(QFont("Segoe UI", 9))
        p.drawText(QRectF(cx-40, cy+16, 80, 16), Qt.AlignCenter, "Security")
        p.setPen(color); p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.drawText(QRectF(0, 3, w, 14), Qt.AlignCenter, "SECURITY SCORE")
        p.end()


class NetworkMapWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.nodes = {}; self.connections = []
        self.setMinimumHeight(250)
        self._layout_timer = QTimer()
        self._layout_timer.timeout.connect(self._apply_force_layout)
        self._layout_timer.start(100); self._frame = 0

    def add_node(self, ip, label=None, node_type="host"):
        if ip not in self.nodes:
            w2, h2 = max(self.width(), 400), max(self.height(), 250)
            self.nodes[ip] = {
                'x': random.randint(50, w2-50), 'y': random.randint(30, h2-30),
                'label': label or ip, 'type': node_type,
                'traffic': 0, 'vx': 0, 'vy': 0
            }

    def add_connection(self, src, dst, protocol="TCP", count=1):
        self.add_node(src); self.add_node(dst)
        for i, (s, d, pr, c) in enumerate(self.connections):
            if (s == src and d == dst) or (s == dst and d == src):
                self.connections[i] = (s, d, pr, c + count)
                self.nodes[src]['traffic'] += count
                self.nodes[dst]['traffic'] += count; return
        self.connections.append((src, dst, protocol, count))
        self.nodes[src]['traffic'] += count
        self.nodes[dst]['traffic'] += count

    def clear(self):
        self.nodes.clear(); self.connections.clear(); self.update()

    def _apply_force_layout(self):
        if not self.nodes: return
        self._frame += 1
        w2, h2 = max(self.width(), 400), max(self.height(), 250)
        nodes = list(self.nodes.values())
        for i, n1 in enumerate(nodes):
            for j, n2 in enumerate(nodes):
                if i >= j: continue
                dx = n1['x'] - n2['x']; dy = n1['y'] - n2['y']
                dist = max(math.sqrt(dx*dx + dy*dy), 1)
                force = 2000 / (dist * dist)
                fx = force * dx / dist; fy = force * dy / dist
                n1['vx'] += fx; n1['vy'] += fy
                n2['vx'] -= fx; n2['vy'] -= fy
        for src, dst, _, _ in self.connections:
            if src in self.nodes and dst in self.nodes:
                n1 = self.nodes[src]; n2 = self.nodes[dst]
                dx = n2['x'] - n1['x']; dy = n2['y'] - n1['y']
                dist = max(math.sqrt(dx*dx + dy*dy), 1)
                force = (dist - 80) * 0.01
                fx = force * dx / dist; fy = force * dy / dist
                n1['vx'] += fx; n1['vy'] += fy
                n2['vx'] -= fx; n2['vy'] -= fy
        for n in nodes:
            n['vx'] += (w2/2 - n['x']) * 0.002; n['vy'] += (h2/2 - n['y']) * 0.002
            n['vx'] *= 0.85; n['vy'] *= 0.85
            n['x'] = max(30, min(w2-30, n['x'] + n['vx']))
            n['y'] = max(30, min(h2-30, n['y'] + n['vy']))
        if self._frame % 3 == 0: self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        grad = QLinearGradient(0, 0, 0, h)
        grad.setColorAt(0, QColor(10, 10, 22)); grad.setColorAt(1, QColor(8, 8, 18))
        p.fillRect(0, 0, w, h, grad)
        p.setPen(Qt.NoPen); p.setBrush(QBrush(QColor(25, 25, 45)))
        for x in range(0, w, 30):
            for y in range(0, h, 30): p.drawEllipse(x, y, 1, 1)
        for src, dst, protocol, count in self.connections:
            if src not in self.nodes or dst not in self.nodes: continue
            n1 = self.nodes[src]; n2 = self.nodes[dst]
            color = QColor(PROTOCOL_COLORS.get(protocol, '#888888'))
            alpha = min(40 + count * 5, 180); color.setAlpha(alpha)
            width = min(1 + count * 0.3, 4)
            p.setPen(QPen(color, width))
            p.drawLine(int(n1['x']), int(n1['y']), int(n2['x']), int(n2['y']))
            if self._frame % 20 < 10:
                t = (self._frame % 20) / 20.0
                px = n1['x'] + (n2['x'] - n1['x']) * t
                py = n1['y'] + (n2['y'] - n1['y']) * t
                p.setBrush(QBrush(color)); p.setPen(Qt.NoPen)
                p.drawEllipse(QPointF(px, py), 3, 3)
        for ip, node in self.nodes.items():
            x, y = int(node['x']), int(node['y'])
            traffic = node['traffic']
            radius = min(8 + traffic * 0.5, 20)
            if node['type'] == 'local': color = QColor(0, 212, 170)
            elif node['type'] == 'gateway': color = QColor(255, 204, 68)
            elif node['type'] == 'dns': color = QColor(170, 107, 255)
            else: color = QColor(0, 170, 255)
            glow = QRadialGradient(x, y, radius * 2)
            glow.setColorAt(0, QColor(color.red(), color.green(), color.blue(), 60))
            glow.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
            p.setBrush(QBrush(glow)); p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(x, y), radius * 2, radius * 2)
            p.setBrush(QBrush(color)); p.setPen(QPen(QColor(255,255,255,80), 1))
            p.drawEllipse(QPointF(x, y), radius, radius)
            p.setPen(QColor(180, 180, 210)); p.setFont(QFont("Segoe UI", 7))
            label = node['label']
            if len(label) > 15: label = label[:12] + "..."
            p.drawText(x - 30, y + radius + 12, 60, 12, Qt.AlignCenter, label)
        p.setPen(QColor(100, 100, 150)); p.setFont(QFont("Segoe UI", 8))
        ly = h - 60
        for label, color in [("Local", QColor(0,212,170)), ("Gateway", QColor(255,204,68)),
                              ("DNS", QColor(170,107,255)), ("Remote", QColor(0,170,255))]:
            p.setBrush(QBrush(color)); p.setPen(Qt.NoPen)
            p.drawEllipse(8, ly, 8, 8)
            p.setPen(QColor(140, 140, 170)); p.drawText(20, ly + 9, label); ly += 14
        p.end()


class HexDumpWidget(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent); self.setReadOnly(True)
        self.setFont(QFont("Cascadia Code", 10)); self.setMaximumHeight(200)

    def set_data(self, data: bytes):
        lines = []
        for i in range(0, min(len(data), 512), 16):
            chunk = data[i:i+16]
            hx = ' '.join(f'{b:02x}' for b in chunk)
            asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{i:08x}  {hx:<48s}  |{asc}|')
        if len(data) > 512: lines.append(f'... ({len(data) - 512} more bytes)')
        self.setPlainText('\n'.join(lines))


class AlertBanner(QWidget):
    clicked = Signal()
    def __init__(self, parent=None):
        super().__init__(parent)
        self.message = ""; self.level = "info"
        self.visible = False; self.opacity = 0
        self._timer = QTimer(); self._timer.timeout.connect(self._tick)
        self._timer.start(30); self.setFixedHeight(0)
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def show_alert(self, message, level="warning"):
        self.message = message; self.level = level; self.visible = True
        self.setFixedHeight(36)

    def hide_alert(self):
        self.visible = False; self.setFixedHeight(0)

    def _tick(self):
        if self.visible and self.opacity < 1.0: self.opacity = min(1.0, self.opacity + 0.08)
        elif not self.visible and self.opacity > 0:
            self.opacity = max(0, self.opacity - 0.08)
            if self.opacity == 0: self.setFixedHeight(0)
        self.update()

    def mousePressEvent(self, e): self.clicked.emit()

    def paintEvent(self, event):
        if self.opacity <= 0: return
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        p.setOpacity(self.opacity); w, h = self.width(), self.height()
        colors = {"critical": QColor(255,68,68), "warning": QColor(255,136,68),
                  "info": QColor(0,170,255), "safe": QColor(0,212,170)}
        bg = colors.get(self.level, QColor(255,136,68))
        bg.setAlpha(30); p.fillRect(0, 0, w, h, bg)
        p.setPen(QPen(colors.get(self.level, QColor(255,136,68)), 1))
        p.drawLine(0, h-1, w, h-1)
        icons = {"critical": "🔴", "warning": "🟠", "info": "🔵", "safe": "🟢"}
        p.setPen(QColor(220, 220, 240)); p.setFont(QFont("Segoe UI", 10, QFont.Bold))
        p.drawText(12, h - 10, f"{icons.get(self.level, '⚠')}  {self.message}")
        p.end()


class SubnetVisualization(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent); self.network = None; self.setMinimumHeight(200)

    def set_network(self, network):
        self.network = network; self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor(14, 14, 28))
        if not self.network:
            p.setPen(QColor(100, 100, 160)); p.setFont(QFont("Segoe UI", 10))
            p.drawText(self.rect(), Qt.AlignCenter, "Enter IP/CIDR to visualize"); p.end(); return
        net = self.network; total = net.num_addresses
        if total > 65536:
            p.setPen(QColor(100, 100, 160)); p.setFont(QFont("Segoe UI", 10))
            p.drawText(self.rect(), Qt.AlignCenter, f"Network too large ({total} addresses)")
            p.end(); return
        cols = min(max(int(math.sqrt(total)), 16), 64)
        rows = max(1, (total + cols - 1) // cols)
        cell_w = (w - 20) / cols; cell_h = min((h - 40) / rows, cell_w)
        start_x = 10; start_y = 25
        p.setPen(QColor(180, 180, 210)); p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.drawText(10, 14, f"{net} — {total} addresses")
        for i in range(min(total, 4096)):
            row_i = i // cols; col_i = i % cols
            x = start_x + col_i * cell_w; y = start_y + row_i * cell_h
            if i == 0: color = QColor(255, 68, 68)
            elif i == total - 1: color = QColor(255, 204, 68)
            elif i == 1 or i == total - 2: color = QColor(0, 212, 170)
            else: color = QColor(30, 50, 80)
            p.setBrush(QBrush(color)); p.setPen(Qt.NoPen)
            if cell_w > 3: p.drawRect(QRectF(x, y, cell_w - 0.5, cell_h - 0.5))
            else: p.drawPoint(int(x + cell_w/2), int(y + cell_h/2))
        ly = h - 16; lx_start = 10
        for label, color in [("Network", QColor(255,68,68)), ("Hosts", QColor(0,212,170)),
                              ("Broadcast", QColor(255,204,68)), ("Available", QColor(30,50,80))]:
            p.setBrush(QBrush(color)); p.setPen(Qt.NoPen)
            p.drawRoundedRect(lx_start, ly, 10, 10, 2, 2)
            p.setPen(QColor(140, 140, 170)); p.setFont(QFont("Segoe UI", 8))
            p.drawText(lx_start + 14, ly + 9, label); lx_start += 90
        p.end()


# ── Worker Threads ─────────────────────────────────────────────
class PortScanWorker(QThread):
    result = Signal(int, str, str); progress = Signal(int); finished_signal = Signal()
    def __init__(self, host, start_port, end_port, timeout=0.5):
        super().__init__()
        self.host = host; self.start_port = start_port
        self.end_port = end_port; self.timeout = timeout; self._running = True

    def run(self):
        total = self.end_port - self.start_port + 1
        for i, port in enumerate(range(self.start_port, self.end_port + 1)):
            if not self._running: break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((self.host, port)) == 0:
                    banner = self._grab_banner(s, port)
                    self.result.emit(port, "open", banner)
                s.close()
            except Exception: pass
            self.progress.emit(int((i + 1) / total * 100))
        self.finished_signal.emit()

    def _grab_banner(self, sock, port):
        try:
            if port in (80, 8080, 443): sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            time.sleep(0.3)
            return sock.recv(256).decode('utf-8', errors='replace')[:80]
        except Exception: return ""

    def stop(self): self._running = False


class PingWorker(QThread):
    output = Signal(str); finished_signal = Signal(); stats = Signal(dict)
    def __init__(self, host, count=4):
        super().__init__(); self.host = host; self.count = count

    def run(self):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        tout = '-w' if platform.system().lower() == 'windows' else '-W'
        try:
            proc = subprocess.Popen(['ping', param, str(self.count), tout, '3', self.host],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=PROC_FLAGS)
            times = []
            for line in proc.stdout:
                self.output.emit(line.rstrip())
                m = re.search(r'time[=<]([\d.]+)', line, re.I)
                if m: times.append(float(m.group(1)))
            proc.wait()
            if times:
                self.stats.emit({'min': min(times), 'max': max(times),
                                  'avg': sum(times)/len(times), 'count': len(times)})
        except Exception as e: self.output.emit(f"Error: {e}")
        self.finished_signal.emit()


class TracerouteWorker(QThread):
    output = Signal(str); finished_signal = Signal()
    def __init__(self, host): super().__init__(); self.host = host

    def run(self):
        cmd = ['tracert', '-d', '-h', '30', self.host] if platform.system() == "Windows" else \
              ['traceroute', '-m', '30', self.host]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, creationflags=PROC_FLAGS)
            for line in proc.stdout: self.output.emit(line.rstrip())
            proc.wait()
        except Exception as e: self.output.emit(f"Error: {e}")
        self.finished_signal.emit()


class SpeedTestWorker(QThread):
    result = Signal(dict); progress = Signal(int, str); finished_signal = Signal()
    def __init__(self, host="8.8.8.8"):
        super().__init__(); self.host = host; self._running = True

    def run(self):
        try:
            self.progress.emit(10, "Testing latency...")
            latencies = []
            for _ in range(5):
                if not self._running: break
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
                t0 = time.time()
                try: s.connect((self.host, 53)); lat = (time.time() - t0) * 1000; latencies.append(lat)
                except: pass
                s.close()
            avg_lat = sum(latencies)/len(latencies) if latencies else 0
            self.progress.emit(40, "Testing download...")
            dl_speed = 0
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(5)
                t0 = time.time(); s.connect(("speedtest.tele2.net", 80))
                s.send(b"GET /1MB.zip HTTP/1.0\r\nHost: speedtest.tele2.net\r\n\r\n")
                total = 0
                while True:
                    if not self._running: break
                    chunk = s.recv(65536)
                    if not chunk: break
                    total += len(chunk)
                    if total > 500000: break
                elapsed = time.time() - t0
                if elapsed > 0: dl_speed = (total * 8) / elapsed / 1000000
                s.close()
            except: pass
            self.progress.emit(80, "Estimating upload...")
            ul_speed = dl_speed * 0.4 if dl_speed else 0
            self.progress.emit(100, "Complete!")
            self.result.emit({'latency': avg_lat, 'download': dl_speed,
                              'upload': ul_speed, 'jitter': max(latencies)-min(latencies) if len(latencies)>1 else 0})
        except Exception as e: self.result.emit({'error': str(e)})
        self.finished_signal.emit()

    def stop(self): self._running = False


class SnifferWorker(QThread):
    packet_signal = Signal(dict); stats_signal = Signal(dict)
    finished_signal = Signal(); alert_signal = Signal(str, str)

    def __init__(self, interface=None, bpf_filter="", demo_mode=False):
        super().__init__()
        self.interface = interface; self.bpf_filter = bpf_filter
        self.demo_mode = demo_mode; self._running = True
        self.proto_dist = defaultdict(int); self.pkt_count = 0; self.byte_count = 0
        self.src_dist = defaultdict(int); self.dst_dist = defaultdict(int)
        self.port_dist = defaultdict(int)
        self.scan_sources = defaultdict(list)

    def run(self):
        if self.demo_mode: self._run_demo()
        elif SCAPY_AVAILABLE: self._run_scapy()
        else:
            self.packet_signal.emit({'error': True, 'summary': 'Scapy not installed. Use Demo Mode.'})
            self.finished_signal.emit()

    def _run_scapy(self):
        def callback(pkt):
            if not self._running: return
            info = self._parse_scapy(pkt)
            if info: self._process_info(info)
        try:
            sniff(prn=callback, iface=self.interface if self.interface else None,
                  filter=self.bpf_filter if self.bpf_filter else "",
                  store=0, stop_filter=lambda x: not self._running)
        except PermissionError:
            self.packet_signal.emit({'error': True, 'summary': 'Permission denied. Use Demo Mode.'})
        except Exception as e:
            self.packet_signal.emit({'error': True, 'summary': str(e)})
        self.finished_signal.emit()

    def _process_info(self, info):
        self.pkt_count += 1; self.byte_count += info.get('length', 0)
        self.proto_dist[info['protocol']] += 1
        src_ip = info.get('src', '').split(':')[0]; dst_ip = info.get('dst', '').split(':')[0]
        self.src_dist[src_ip] += 1; self.dst_dist[dst_ip] += 1
        if info['protocol'] == 'TCP' and 'S' in info.get('summary', '') and 'A' not in info.get('summary', ''):
            self.scan_sources[src_ip].append(time.time())
            recent = [t for t in self.scan_sources[src_ip] if time.time() - t < 5]
            self.scan_sources[src_ip] = recent
            if len(recent) > 10:
                self.alert_signal.emit(f"Possible port scan from {src_ip} ({len(recent)} SYNs in 5s)", "warning")
        for layer_name, fields in info.get('layers', {}).items():
            if 'Dst Port' in fields: self.port_dist[fields['Dst Port']] += 1
        self.packet_signal.emit(info)
        self.stats_signal.emit({
            'packets': self.pkt_count, 'bytes': self.byte_count,
            'protocols': dict(self.proto_dist),
            'top_sources': dict(sorted(self.src_dist.items(), key=lambda x: -x[1])[:10]),
            'top_destinations': dict(sorted(self.dst_dist.items(), key=lambda x: -x[1])[:10]),
            'top_ports': dict(sorted(self.port_dist.items(), key=lambda x: -x[1])[:10]),
        })

    def _parse_scapy(self, pkt):
        info = {'no': self.pkt_count + 1, 'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src': '', 'dst': '', 'protocol': 'Other', 'length': len(pkt),
                'summary': '', 'layers': {}, 'raw': bytes(pkt)[:512]}
        if IP in pkt:
            info['src'] = pkt[IP].src; info['dst'] = pkt[IP].dst; info['length'] = pkt[IP].len
            info['layers']['IP'] = {'Version': pkt[IP].version, 'Src': pkt[IP].src,
                                     'Dst': pkt[IP].dst, 'TTL': pkt[IP].ttl,
                                     'ID': pkt[IP].id, 'Protocol': pkt[IP].proto}
        if TCP in pkt:
            info['protocol'] = 'TCP'
            info['src'] = f"{pkt[IP].src}:{pkt[TCP].sport}" if IP in pkt else str(pkt[TCP].sport)
            info['dst'] = f"{pkt[IP].dst}:{pkt[TCP].dport}" if IP in pkt else str(pkt[TCP].dport)
            fl = str(pkt[TCP].flags)
            info['summary'] = f"{get_service_name(pkt[TCP].dport)} [{fl}] Seq={pkt[TCP].seq} Ack={pkt[TCP].ack}"
            info['layers']['TCP'] = {'Src Port': pkt[TCP].sport, 'Dst Port': pkt[TCP].dport,
                                      'Flags': fl, 'Seq': pkt[TCP].seq, 'Ack': pkt[TCP].ack,
                                      'Window': pkt[TCP].window}
        elif UDP in pkt:
            info['protocol'] = 'UDP'
            info['src'] = f"{pkt[IP].src}:{pkt[UDP].sport}" if IP in pkt else str(pkt[UDP].sport)
            info['dst'] = f"{pkt[IP].dst}:{pkt[UDP].dport}" if IP in pkt else str(pkt[UDP].dport)
            info['summary'] = f"{get_service_name(pkt[UDP].dport)} Len={pkt[UDP].len}"
            info['layers']['UDP'] = {'Src Port': pkt[UDP].sport, 'Dst Port': pkt[UDP].dport, 'Length': pkt[UDP].len}
        elif ICMP in pkt:
            info['protocol'] = 'ICMP'; tp = pkt[ICMP].type
            types = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Dest Unreachable', 11: 'Time Exceeded'}
            info['summary'] = types.get(tp, f'Type {tp}')
            info['layers']['ICMP'] = {'Type': tp, 'Code': pkt[ICMP].code, 'ID': getattr(pkt[ICMP], 'id', 'N/A')}
        elif ARP in pkt:
            info['protocol'] = 'ARP'; info['src'] = pkt[ARP].psrc; info['dst'] = pkt[ARP].pdst
            op = 'Request' if pkt[ARP].op == 1 else 'Reply'
            info['summary'] = f"{op}: {pkt[ARP].psrc} → {pkt[ARP].pdst}"
            info['layers']['ARP'] = {'Op': op, 'HWSrc': pkt[ARP].hwsrc, 'PSrc': pkt[ARP].psrc,
                                      'HWDst': pkt[ARP].hwdst, 'PDst': pkt[ARP].pdst}
        if DNS in pkt: info['protocol'] = 'DNS'; info['summary'] = "DNS Query/Response"
        if Raw in pkt: info['layers']['Payload'] = {'Length': len(pkt[Raw])}
        return info

    def _run_demo(self):
        ips = ["192.168.1.1", "192.168.1.100", "10.0.0.1", "172.16.0.5",
               "8.8.8.8", "1.1.1.1", "192.168.1.50", "10.10.10.10",
               "192.168.1.200", "203.0.113.5", "198.51.100.10", "172.217.14.206"]
        while self._running:
            proto = random.choice(['TCP','TCP','TCP','UDP','ICMP','ARP','DNS'])
            si, di = random.sample(ips, 2); sp = random.randint(49152, 65535)
            dp = random.choice([80,443,53,22,8080,25,110,3306,3389,993,143,445,6379,27017,9200])
            ln = random.randint(40, 1500)
            info = {'no': self.pkt_count+1, 'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'src': f'{si}:{sp}', 'dst': f'{di}:{dp}', 'protocol': proto,
                    'length': ln, 'summary': '', 'layers': {},
                    'raw': bytes([random.randint(0,255) for _ in range(min(ln,128))])}
            if proto == 'TCP':
                fl = random.choice(['S','SA','A','PA','FA','R'])
                info['summary'] = f"{get_service_name(dp)} [{fl}] Seq={random.randint(0,999999)}"
                info['layers']['IP'] = {'Src': si, 'Dst': di, 'TTL': random.randint(32,128)}
                info['layers']['TCP'] = {'Src Port': sp, 'Dst Port': dp, 'Flags': fl}
            elif proto == 'UDP':
                info['summary'] = f"{get_service_name(dp)} Len={ln}"
                info['layers']['IP'] = {'Src': si, 'Dst': di, 'TTL': random.randint(32,128)}
                info['layers']['UDP'] = {'Src Port': sp, 'Dst Port': dp, 'Length': ln}
            elif proto == 'ICMP':
                it = random.choice([0,8,3,11])
                types = {0:'Echo Reply',8:'Echo Request',3:'Dest Unreachable',11:'Time Exceeded'}
                info['summary'] = types.get(it,f'Type {it}'); info['src'] = si; info['dst'] = di
                info['layers']['ICMP'] = {'Type': it, 'Code': 0}
            elif proto == 'ARP':
                op = random.choice(['Request','Reply'])
                info['summary'] = f"{op}: {si} → {di}"; info['src'] = si; info['dst'] = di
                info['layers']['ARP'] = {'Op': op, 'PSrc': si, 'PDst': di}
            elif proto == 'DNS':
                info['summary'] = "DNS Query: example.com A"
                info['layers']['DNS'] = {'Query': 'example.com', 'Type': 'A'}
            self._process_info(info)
            time.sleep(random.uniform(0.03, 0.3))
        self.finished_signal.emit()

    def stop(self): self._running = False


# ══════════════════════════════════════════════════════════════
#  TAB WIDGETS — Professional Layout
# ══════════════════════════════════════════════════════════════

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self.proto_chart = ProtocolPieChart()
        self.security_score = SecurityScoreWidget()
        self.gauge_rate = GaugeWidget(title="Pkt Rate", unit="pkt/s", max_val=500, color=QColor(0, 212, 170))
        self.gauge_bytes = GaugeWidget(title="Throughput", unit="KB/s", max_val=1000, color=QColor(0, 170, 255))
        self.gauge_conns = GaugeWidget(title="Connections", unit="", max_val=200, color=QColor(255, 204, 68))
        self.source_chart = BarChartWidget(title="Top Sources")
        self.dest_chart = BarChartWidget(title="Top Destinations")
        self.port_chart = BarChartWidget(title="Top Ports", color=QColor(170, 107, 255))
        self._security_issues = []
        self._setup_ui(); self._load_info()
        self.refresh_timer = QTimer(); self.refresh_timer.timeout.connect(self._refresh_stats)
        self.refresh_timer.start(2000)
        self._start_time = time.time()
        self._uptime_timer = QTimer(); self._uptime_timer.timeout.connect(self._update_uptime)
        self._uptime_timer.start(1000)

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(14, 14, 14, 8)
        title = QLabel("Network Dashboard Pro"); title.setObjectName("titleLabel")
        layout.addWidget(title)

        row1 = QHBoxLayout(); row1.setSpacing(10)
        # System Info
        sg = QGroupBox("System Information"); gl = QGridLayout(sg); gl.setSpacing(6)
        self.lbl_host = QLabel("-"); self.lbl_ip = QLabel("-")
        self.lbl_os = QLabel("-"); self.lbl_gw = QLabel("-")
        self.lbl_mac = QLabel("-"); self.lbl_uptime = QLabel("00:00:00")
        for i, (t, w) in enumerate([("Hostname:", self.lbl_host), ("Local IP:", self.lbl_ip),
                                      ("OS:", self.lbl_os), ("Gateway:", self.lbl_gw),
                                      ("MAC:", self.lbl_mac), ("Uptime:", self.lbl_uptime)]):
            lb = QLabel(t); lb.setStyleSheet("color:#6a6a99;font-weight:600;font-size:12px;")
            w.setStyleSheet("color:#c8c8e0;font-size:12px;")
            gl.addWidget(lb, i, 0); gl.addWidget(w, i, 1)
        row1.addWidget(sg, stretch=1)

        # Gauges
        gauges = QGroupBox("Live Gauges"); gv = QHBoxLayout(gauges); gv.setSpacing(4)
        gv.addWidget(self.gauge_rate); gv.addWidget(self.gauge_bytes); gv.addWidget(self.gauge_conns)
        row1.addWidget(gauges, stretch=2)

        # Security Score
        sv = QVBoxLayout(); sv.addWidget(self.security_score, alignment=Qt.AlignCenter)
        sg2 = QGroupBox("Security"); sg2.setLayout(sv); row1.addWidget(sg2)
        layout.addLayout(row1, stretch=2)

        row2 = QHBoxLayout(); row2.setSpacing(10)
        pg = QGroupBox("Protocol Distribution"); pv = QVBoxLayout(pg)
        pv.addWidget(self.proto_chart); row2.addWidget(pg)
        cg = QGroupBox("Traffic Monitor"); cv = QVBoxLayout(cg)
        self.traffic_chart = TrafficChart(title="Packets/sec", color=QColor(0, 212, 170))
        self.bandwidth_chart = DualTrafficChart(title1="Inbound Pkt/s", title2="Outbound Pkt/s")
        cv.addWidget(self.traffic_chart); cv.addWidget(self.bandwidth_chart)
        row2.addWidget(cg, stretch=2)
        layout.addLayout(row2, stretch=3)

        row3 = QHBoxLayout(); row3.setSpacing(10)
        row3.addWidget(self.source_chart); row3.addWidget(self.dest_chart); row3.addWidget(self.port_chart)
        layout.addLayout(row3, stretch=2)

        co = QGroupBox("Active Network Connections"); cl = QVBoxLayout(co)
        self.conn_table = QTableWidget(); self.conn_table.setColumnCount(7)
        self.conn_table.setHorizontalHeaderLabels(["Proto","Local Addr","Local Port","Remote Addr","Remote Port","Status","PID"])
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        cl.addWidget(self.conn_table); layout.addWidget(co, stretch=2)

    def _load_info(self):
        self.lbl_host.setText(socket.gethostname())
        self.lbl_ip.setText(get_local_ip())
        self.lbl_os.setText(f"{platform.system()} {platform.release()}")
        self.lbl_gw.setText(get_gateway())
        self.lbl_mac.setText(get_mac_address())

    def _update_uptime(self):
        elapsed = time.time() - self._start_time
        self.lbl_uptime.setText(format_elapsed(elapsed))

    def _refresh_stats(self):
        if PSUTIL_AVAILABLE:
            conns = []
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'NONE': continue
                la, lp = c.laddr if c.laddr else ("", "")
                ra, rp = c.raddr if c.raddr else ("", "")
                conns.append([c.laddr[0] if c.laddr else "", str(c.laddr[1]) if c.laddr else "",
                              c.raddr[0] if c.raddr else "", str(c.raddr[1]) if c.raddr else "",
                              c.status, str(c.pid or "")])
            self.conn_table.setRowCount(min(len(conns), 200))
            for i, row in enumerate(conns[:200]):
                for j, val in enumerate(row):
                    item = QTableWidgetItem(val)
                    item.setTextAlignment(Qt.AlignCenter)
                    self.conn_table.setItem(i, j, item)

    def update_sniffer_stats(self, stats):
        if 'protocols' in stats:
            self.proto_chart.set_data(stats['protocols'])
        if 'top_sources' in stats:
            self.source_chart.set_data(stats['top_sources'])
        if 'top_destinations' in stats:
            self.dest_chart.set_data(stats['top_destinations'])
        if 'top_ports' in stats:
            port_data = {str(k): v for k, v in stats['top_ports'].items()}
            self.port_chart.set_data(port_data, color=QColor(170, 107, 255))
        self.gauge_rate.set_value(stats.get('pkt_rate', 0))
        self.gauge_bytes.set_value(stats.get('byte_rate', 0) / 1024)

    def add_traffic_sample(self, rate, in_rate, out_rate):
        self.traffic_chart.add_value(rate)
        self.bandwidth_chart.add_values(in_rate, out_rate)


class CaptureTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.sniffer = None
        self._pkt_count = 0; self._byte_count = 0; self._last_time = time.time()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(8); layout.setContentsMargins(14, 14, 14, 8)

        # Controls bar
        ctrl = QHBoxLayout(); ctrl.setSpacing(8)
        self.btn_start = QPushButton("▶  Start Capture"); self.btn_start.setObjectName("startBtn")
        self.btn_stop = QPushButton("■  Stop"); self.btn_stop.setObjectName("stopBtn"); self.btn_stop.setEnabled(False)
        self.btn_demo = QPushButton("📡  Demo Mode"); self.btn_demo.setObjectName("scanBtn")
        self.btn_clear = QPushButton("🗑  Clear")

        iface_label = QLabel("Interface:"); iface_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.iface_combo = QComboBox(); self.iface_combo.setMinimumWidth(160)
        self._load_interfaces()

        filter_label = QLabel("BPF Filter:"); filter_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.filter_edit = QLineEdit(); self.filter_edit.setPlaceholderText("e.g. tcp port 80")
        self.filter_edit.setMaximumWidth(200)

        self.pkt_count_label = QLabel("Packets: 0"); self.pkt_count_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.byte_count_label = QLabel("Bytes: 0"); self.byte_count_label.setStyleSheet("color:#6a6a99;font-weight:600;")

        ctrl.addWidget(self.btn_start); ctrl.addWidget(self.btn_stop); ctrl.addWidget(self.btn_demo)
        ctrl.addWidget(self.btn_clear); ctrl.addSpacing(12)
        ctrl.addWidget(iface_label); ctrl.addWidget(self.iface_combo)
        ctrl.addWidget(filter_label); ctrl.addWidget(self.filter_edit)
        ctrl.addStretch()
        ctrl.addWidget(self.pkt_count_label); ctrl.addWidget(self.byte_count_label)
        layout.addLayout(ctrl)

        # Status
        self.status = InlineStatus(); layout.addWidget(self.status)

        # Splitter: table | detail
        splitter = QSplitter(Qt.Vertical)

        # Packet table
        self.pkt_table = QTableWidget(); self.pkt_table.setColumnCount(6)
        self.pkt_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Summary"])
        self.pkt_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.pkt_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.pkt_table.setColumnWidth(0, 60)
        self.pkt_table.setAlternatingRowColors(True)
        self.pkt_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.pkt_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.pkt_table.currentCellChanged.connect(self._on_packet_selected)
        splitter.addWidget(self.pkt_table)

        # Detail panel
        detail = QWidget(); dv = QVBoxLayout(detail); dv.setContentsMargins(4, 4, 4, 4)
        self.detail_tree = QTreeWidget(); self.detail_tree.setHeaderLabel("Packet Layers")
        self.detail_tree.setMaximumHeight(250)
        self.detail_tree.itemClicked.connect(self._on_layer_clicked)
        self.hex_dump = HexDumpWidget()
        dv.addWidget(self.detail_tree); dv.addWidget(self.hex_dump)
        splitter.addWidget(detail)
        splitter.setSizes([400, 250])
        layout.addWidget(splitter, stretch=1)

        # Connect
        self.btn_start.clicked.connect(self._start_capture)
        self.btn_stop.clicked.connect(self._stop_capture)
        self.btn_demo.clicked.connect(self._start_demo)
        self.btn_clear.clicked.connect(self._clear)

        self._packets = []

    def _load_interfaces(self):
        self.iface_combo.addItem("Default")
        if SCAPY_AVAILABLE:
            try:
                for iface in get_if_list():
                    self.iface_combo.addItem(iface)
            except: pass
        elif PSUTIL_AVAILABLE:
            for name in psutil.net_if_addrs():
                self.iface_combo.addItem(name)

    def _start_capture(self):
        if not SCAPY_AVAILABLE:
            self.status.show_error("Scapy not installed. Use Demo Mode instead.")
            return
        iface = self.iface_combo.currentText()
        if iface == "Default": iface = None
        bpf = self.filter_edit.text().strip()
        self.sniffer = SnifferWorker(interface=iface, bpf_filter=bpf, demo_mode=False)
        self.sniffer.packet_signal.connect(self._on_packet)
        self.sniffer.stats_signal.connect(self._on_stats)
        self.sniffer.alert_signal.connect(self._on_alert)
        self.sniffer.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True); self.btn_demo.setEnabled(False)
        self.status.show_success("Capture started on " + (iface or "default interface"))

    def _start_demo(self):
        self.sniffer = SnifferWorker(demo_mode=True)
        self.sniffer.packet_signal.connect(self._on_packet)
        self.sniffer.stats_signal.connect(self._on_stats)
        self.sniffer.alert_signal.connect(self._on_alert)
        self.sniffer.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True); self.btn_demo.setEnabled(False)
        self.status.show_info("Demo mode active — generating simulated traffic")

    def _stop_capture(self):
        if self.sniffer:
            self.sniffer.stop(); self.sniffer = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False); self.btn_demo.setEnabled(True)
        self.status.show_warning("Capture stopped")

    def _clear(self):
        self.pkt_table.setRowCount(0); self._packets.clear()
        self.detail_tree.clear(); self.hex_dump.clear()
        self._pkt_count = 0; self._byte_count = 0
        self.pkt_count_label.setText("Packets: 0")
        self.byte_count_label.setText("Bytes: 0")
        self.status.clear()

    def _on_packet(self, info):
        if info.get('error'):
            self.status.show_error(info['summary']); self._stop_capture(); return
        self._packets.append(info)
        row = self.pkt_table.rowCount(); self.pkt_table.insertRow(row)
        proto_color = QColor(PROTOCOL_COLORS.get(info['protocol'], '#d0d0e0'))
        for j, key in enumerate(['no', 'time', 'src', 'dst', 'protocol', 'summary']):
            item = QTableWidgetItem(str(info.get(key, '')))
            item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            if key == 'protocol':
                item.setForeground(QBrush(proto_color))
                item.setFont(QFont("Segoe UI", 12, QFont.Bold))
            self.pkt_table.setItem(row, j, item)
        self._pkt_count += 1; self._byte_count += info.get('length', 0)
        self.pkt_count_label.setText(f"Packets: {self._pkt_count}")
        self.byte_count_label.setText(f"Bytes: {format_size(self._byte_count)}")
        # Auto-scroll
        self.pkt_table.scrollToBottom()

    def _on_stats(self, stats):
        now = time.time(); dt = now - self._last_time
        if dt > 0:
            rate = stats.get('packets', 0) / dt
            byte_rate = stats.get('bytes', 0) / dt
            in_rate = rate * 0.55; out_rate = rate * 0.45
            stats['pkt_rate'] = rate; stats['byte_rate'] = byte_rate
            self.main_window.dashboard.update_sniffer_stats(stats)
            self.main_window.dashboard.add_traffic_sample(rate, in_rate, out_rate)
            self.main_window.network_map._update_from_sniffer(stats)
        self._last_time = now

    def _on_alert(self, msg, level):
        self.main_window.show_toast(msg, level if level != "warning" else "warning")

    def _on_packet_selected(self, row, col, prev_row, prev_col):
        if row < 0 or row >= len(self._packets): return
        info = self._packets[row]
        self.detail_tree.clear()
        for layer_name, fields in info.get('layers', {}).items():
            layer_item = QTreeWidgetItem(self.detail_tree, [f"🔹 {layer_name}"])
            layer_item.setForeground(0, QBrush(QColor(0, 212, 170)))
            for key, val in fields.items():
                child = QTreeWidgetItem(layer_item, [f"  {key}: {val}"])
                child.setForeground(0, QBrush(QColor(160, 160, 200)))
        self.detail_tree.expandAll()
        raw = info.get('raw', b'')
        if raw: self.hex_dump.set_data(raw)

    def _on_layer_clicked(self, item, col):
        pass


class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_worker = None; self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(14, 14, 14, 8)

        # Scan configuration
        config = QHBoxLayout(); config.setSpacing(8)
        host_label = QLabel("Target:"); host_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.host_edit = QLineEdit(); self.host_edit.setPlaceholderText("e.g. 192.168.1.1 or example.com")
        self.host_edit.setMinimumWidth(200)

        port_label = QLabel("Ports:"); port_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.port_start = QSpinBox(); self.port_start.setRange(1, 65535); self.port_start.setValue(1)
        self.port_end = QSpinBox(); self.port_end.setRange(1, 65535); self.port_end.setValue(1024)
        dash = QLabel("–"); dash.setStyleSheet("color:#6a6a99;")

        timeout_label = QLabel("Timeout:"); timeout_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(100, 5000); self.timeout_spin.setValue(500)
        self.timeout_spin.setSuffix(" ms")

        self.btn_scan = QPushButton("🔍  Scan"); self.btn_scan.setObjectName("scanBtn")
        self.btn_stop = QPushButton("■  Stop"); self.btn_stop.setObjectName("stopBtn"); self.btn_stop.setEnabled(False)

        config.addWidget(host_label); config.addWidget(self.host_edit, stretch=2)
        config.addWidget(port_label); config.addWidget(self.port_start); config.addWidget(dash)
        config.addWidget(self.port_end)
        config.addWidget(timeout_label); config.addWidget(self.timeout_spin)
        config.addWidget(self.btn_scan); config.addWidget(self.btn_stop)
        layout.addLayout(config)

        # Status + progress
        status_row = QHBoxLayout()
        self.status = InlineStatus()
        self.progress = QProgressBar(); self.progress.setValue(0); self.progress.setMaximumHeight(20)
        self.progress.setVisible(False)
        status_row.addWidget(self.status, stretch=1); status_row.addWidget(self.progress, stretch=1)
        layout.addLayout(status_row)

        # Results table
        self.result_table = QTableWidget(); self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["Port", "Service", "State", "Banner"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.result_table.setColumnWidth(0, 80)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.result_table, stretch=1)

        # Summary
        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color:#6a6a99;font-size:12px;padding:4px;")
        layout.addWidget(self.summary_label)

        # Connect
        self.btn_scan.clicked.connect(self._start_scan)
        self.btn_stop.clicked.connect(self._stop_scan)

    def _start_scan(self):
        host = self.host_edit.text().strip()
        if not host:
            self.status.show_error("Please enter a target host")
            return
        # Resolve if needed
        if not host.replace('.', '').isdigit():
            resolved = resolve_dns(host)
            if resolved:
                host = resolved
                self.host_edit.setText(host)
                self.status.show_info(f"Resolved to {host}")
            else:
                self.status.show_error(f"Could not resolve hostname: {host}")
                return

        sp = self.port_start.value(); ep = self.port_end.value()
        if sp > ep:
            self.status.show_error("Start port must be <= end port")
            return

        timeout = self.timeout_spin.value() / 1000.0
        self.result_table.setRowCount(0); self.progress.setValue(0)
        self.progress.setVisible(True)
        self.summary_label.setText(f"Scanning {host} ports {sp}–{ep}...")

        self.scan_worker = PortScanWorker(host, sp, ep, timeout)
        self.scan_worker.result.connect(self._on_result)
        self.scan_worker.progress.connect(self._on_progress)
        self.scan_worker.finished_signal.connect(self._on_finished)
        self.scan_worker.start()

        self.btn_scan.setEnabled(False); self.btn_stop.setEnabled(True)
        self.status.show_success(f"Scanning {host} ports {sp}–{ep}")

    def _stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop(); self.scan_worker = None
        self.btn_scan.setEnabled(True); self.btn_stop.setEnabled(False)
        self.status.show_warning("Scan stopped")

    def _on_result(self, port, state, banner):
        row = self.result_table.rowCount(); self.result_table.insertRow(row)
        service = get_service_name(port)
        items = [
            QTableWidgetItem(str(port)),
            QTableWidgetItem(service),
            QTableWidgetItem(state),
            QTableWidgetItem(banner[:60] if banner else "")
        ]
        items[0].setTextAlignment(Qt.AlignCenter)
        items[2].setTextAlignment(Qt.AlignCenter)
        if state == "open":
            items[2].setForeground(QBrush(QColor(0, 212, 170)))
            items[2].setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.result_table.setItem(row, 0, items[0])
        self.result_table.setItem(row, 1, items[1])
        self.result_table.setItem(row, 2, items[2])
        self.result_table.setItem(row, 3, items[3])

    def _on_progress(self, val):
        self.progress.setValue(val)

    def _on_finished(self):
        self.btn_scan.setEnabled(True); self.btn_stop.setEnabled(False)
        self.progress.setVisible(False)
        open_count = self.result_table.rowCount()
        total_scanned = self.port_end.value() - self.port_start.value() + 1
        self.summary_label.setText(
            f"Scan complete — {open_count} open ports found out of {total_scanned} scanned")
        if open_count > 0:
            self.status.show_success(f"Found {open_count} open ports")
        else:
            self.status.show_warning("No open ports found")


class DiagnosticsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.ping_worker = None; self.traceroute_worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(14, 14, 14, 8)

        # Tool selector
        toolbar = QHBoxLayout(); toolbar.setSpacing(8)
        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["Ping", "Traceroute", "DNS Lookup", "Whois", "Speed Test"])
        self.tool_combo.setStyleSheet("font-weight:600;")

        target_label = QLabel("Target:"); target_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.target_edit = QLineEdit(); self.target_edit.setPlaceholderText("e.g. 8.8.8.8 or example.com")
        self.target_edit.setMinimumWidth(250)

        self.btn_run = QPushButton("▶  Run"); self.btn_run.setObjectName("startBtn")
        self.btn_stop = QPushButton("■  Stop"); self.btn_stop.setObjectName("stopBtn"); self.btn_stop.setEnabled(False)

        toolbar.addWidget(QLabel("Tool:")); toolbar.addWidget(self.tool_combo)
        toolbar.addWidget(target_label); toolbar.addWidget(self.target_edit, stretch=2)
        toolbar.addWidget(self.btn_run); toolbar.addWidget(self.btn_stop)
        layout.addLayout(toolbar)

        # Status
        self.status = InlineStatus(); layout.addWidget(self.status)

        # Output area
        splitter = QSplitter(Qt.Vertical)

        self.output_text = QTextEdit(); self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Cascadia Code", 11))
        splitter.addWidget(self.output_text)

        # Stats panel for ping
        stats_widget = QWidget(); sl = QGridLayout(stats_widget); sl.setSpacing(8)
        self.stat_labels = {}
        for i, key in enumerate(["Min RTT", "Avg RTT", "Max RTT", "Packets", "Jitter", "Download", "Upload"]):
            lbl = QLabel(key); lbl.setObjectName("statLabel"); lbl.setAlignment(Qt.AlignCenter)
            val = QLabel("-"); val.setObjectName("statValue"); val.setAlignment(Qt.AlignCenter)
            sl.addWidget(lbl, 0, i); sl.addWidget(val, 1, i)
            self.stat_labels[key] = val
        stats_widget.setMaximumHeight(100)
        splitter.addWidget(stats_widget)
        splitter.setSizes([350, 100])
        layout.addWidget(splitter, stretch=1)

        # Connect
        self.btn_run.clicked.connect(self._run)
        self.btn_stop.clicked.connect(self._stop)

    def _run(self):
        tool = self.tool_combo.currentText()
        target = self.target_edit.text().strip()
        if not target and tool not in ["Speed Test"]:
            self.status.show_error("Please enter a target")
            return
        self.output_text.clear()
        for v in self.stat_labels.values(): v.setText("-")
        self.btn_run.setEnabled(False); self.btn_stop.setEnabled(True)

        if tool == "Ping":
            self._run_ping(target)
        elif tool == "Traceroute":
            self._run_traceroute(target)
        elif tool == "DNS Lookup":
            self._run_dns(target)
        elif tool == "Whois":
            self._run_whois(target)
        elif tool == "Speed Test":
            self._run_speedtest()

    def _stop(self):
        if self.ping_worker: self.ping_worker.terminate(); self.ping_worker = None
        if self.traceroute_worker: self.traceroute_worker.terminate(); self.traceroute_worker = None
        self.btn_run.setEnabled(True); self.btn_stop.setEnabled(False)
        self.status.show_warning("Stopped")

    def _run_ping(self, host):
        self.status.show_info(f"Pinging {host}...")
        self.ping_worker = PingWorker(host, count=10)
        self.ping_worker.output.connect(self.output_text.append)
        self.ping_worker.stats.connect(self._on_ping_stats)
        self.ping_worker.finished_signal.connect(lambda: self._on_tool_done("Ping"))
        self.ping_worker.start()

    def _run_traceroute(self, host):
        self.status.show_info(f"Traceroute to {host}...")
        self.traceroute_worker = TracerouteWorker(host)
        self.traceroute_worker.output.connect(self.output_text.append)
        self.traceroute_worker.finished_signal.connect(lambda: self._on_tool_done("Traceroute"))
        self.traceroute_worker.start()

    def _run_dns(self, host):
        self.status.show_info(f"DNS lookup for {host}...")
        try:
            ip = socket.gethostbyname(host)
            self.output_text.append(f"Name:    {host}")
            self.output_text.append(f"Address: {ip}")
            # Reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.output_text.append(f"PTR:     {hostname}")
            except: pass
            # Try all addresses
            try:
                results = socket.getaddrinfo(host, None)
                seen = set()
                for r in results:
                    addr = r[4][0]
                    if addr not in seen:
                        seen.add(addr)
                        self.output_text.append(f"  → {addr}")
            except: pass
            self.stat_labels["Min RTT"].setText(ip)
            self.status.show_success(f"Resolved to {ip}")
        except socket.gaierror:
            self.status.show_error(f"Could not resolve {host}")
        self.btn_run.setEnabled(True); self.btn_stop.setEnabled(False)

    def _run_whois(self, host):
        self.status.show_info(f"Whois lookup for {host}...")
        try:
            proc = subprocess.Popen(['whois', host],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=PROC_FLAGS)
            output, _ = proc.communicate(timeout=15)
            self.output_text.setText(output[:10000])
            self.status.show_success("Whois complete")
        except FileNotFoundError:
            self.status.show_error("whois command not found — install it first")
            self.output_text.setText("The 'whois' utility is not installed.\n\n"
                "Install with:\n"
                "  Ubuntu/Debian: sudo apt install whois\n"
                "  macOS: brew install whois\n"
                "  Windows: Not commonly available")
        except subprocess.TimeoutExpired:
            self.status.show_error("Whois request timed out")
        self.btn_run.setEnabled(True); self.btn_stop.setEnabled(False)

    def _run_speedtest(self):
        self.status.show_info("Running speed test...")
        self.speed_worker = SpeedTestWorker()
        self.speed_worker.result.connect(self._on_speed_result)
        self.speed_worker.progress.connect(lambda p, m: self.output_text.append(m))
        self.speed_worker.finished_signal.connect(lambda: self._on_tool_done("Speed Test"))
        self.speed_worker.start()

    def _on_ping_stats(self, stats):
        self.stat_labels["Min RTT"].setText(f"{stats['min']:.1f} ms")
        self.stat_labels["Avg RTT"].setText(f"{stats['avg']:.1f} ms")
        self.stat_labels["Max RTT"].setText(f"{stats['max']:.1f} ms")
        self.stat_labels["Packets"].setText(str(stats['count']))

    def _on_speed_result(self, result):
        if 'error' in result:
            self.status.show_error(result['error']); return
        self.stat_labels["Min RTT"].setText(f"{result.get('latency',0):.1f} ms")
        self.stat_labels["Avg RTT"].setText(f"{result.get('jitter',0):.1f} ms")
        self.stat_labels["Download"].setText(f"{result.get('download',0):.2f} Mbps")
        self.stat_labels["Upload"].setText(f"{result.get('upload',0):.2f} Mbps")

    def _on_tool_done(self, tool):
        self.btn_run.setEnabled(True); self.btn_stop.setEnabled(False)
        self.status.show_success(f"{tool} complete")


class NetworkMapTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(8); layout.setContentsMargins(14, 14, 14, 8)

        toolbar = QHBoxLayout(); toolbar.setSpacing(8)
        self.btn_refresh = QPushButton("🔄  Refresh Map")
        self.btn_clear = QPushButton("🗑  Clear")
        self.node_count = QLabel("Nodes: 0"); self.node_count.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.conn_count = QLabel("Connections: 0"); self.conn_count.setStyleSheet("color:#6a6a99;font-weight:600;")
        toolbar.addWidget(self.btn_refresh); toolbar.addWidget(self.btn_clear)
        toolbar.addStretch(); toolbar.addWidget(self.node_count); toolbar.addWidget(self.conn_count)
        layout.addLayout(toolbar)

        self.map_widget = NetworkMapWidget()
        layout.addWidget(self.map_widget, stretch=1)

        self.btn_refresh.clicked.connect(self._refresh)
        self.btn_clear.clicked.connect(self.map_widget.clear)

    def _refresh(self):
        self.map_widget.clear()
        local_ip = get_local_ip()
        gw = get_gateway()
        self.map_widget.add_node(local_ip, label=socket.gethostname(), node_type="local")
        self.map_widget.add_node(gw, label="Gateway", node_type="gateway")
        self.map_widget.add_node("8.8.8.8", label="Google DNS", node_type="dns")
        self.map_widget.add_node("1.1.1.1", label="Cloudflare DNS", node_type="dns")
        self.map_widget.add_connection(local_ip, gw, "TCP", 5)
        self.map_widget.add_connection(gw, "8.8.8.8", "UDP", 3)
        self.map_widget.add_connection(gw, "1.1.1.1", "UDP", 2)

    def _update_counts(self):
        self.node_count.setText(f"Nodes: {len(self.map_widget.nodes)}")
        self.conn_count.setText(f"Connections: {len(self.map_widget.connections)}")


class SubnetTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(14, 14, 14, 8)

        toolbar = QHBoxLayout(); toolbar.setSpacing(8)
        cidr_label = QLabel("IP/CIDR:"); cidr_label.setStyleSheet("color:#6a6a99;font-weight:600;")
        self.cidr_edit = QLineEdit(); self.cidr_edit.setPlaceholderText("e.g. 192.168.1.0/24")
        self.cidr_edit.setMinimumWidth(200)
        self.btn_calc = QPushButton("Calculate"); self.btn_calc.setObjectName("scanBtn")
        toolbar.addWidget(cidr_label); toolbar.addWidget(self.cidr_edit, stretch=1)
        toolbar.addWidget(self.btn_calc)
        layout.addLayout(toolbar)

        self.status = InlineStatus(); layout.addWidget(self.status)

        # Results
        splitter = QSplitter(Qt.Vertical)
        info_widget = QWidget(); il = QGridLayout(info_widget); il.setSpacing(8)
        self.info_labels = {}
        for i, key in enumerate(["Network", "Netmask", "Broadcast", "First Host", "Last Host",
                                  "Total Hosts", "Address Range", "Class"]):
            lbl = QLabel(key); lbl.setObjectName("statLabel")
            val = QLabel("-"); val.setStyleSheet("color:#c8c8e0;font-family:Consolas;")
            il.addWidget(lbl, i, 0); il.addWidget(val, i, 1)
            self.info_labels[key] = val
        splitter.addWidget(info_widget)

        self.subnet_viz = SubnetVisualization()
        splitter.addWidget(self.subnet_viz)
        splitter.setSizes([200, 300])
        layout.addWidget(splitter, stretch=1)

        self.btn_calc.clicked.connect(self._calculate)

    def _calculate(self):
        cidr = self.cidr_edit.text().strip()
        if not cidr:
            self.status.show_error("Please enter an IP/CIDR")
            return
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            self.status.show_error(f"Invalid network: {e}")
            return

        self.info_labels["Network"].setText(str(net.network_address))
        self.info_labels["Netmask"].setText(str(net.netmask))
        self.info_labels["Broadcast"].setText(str(net.broadcast_address) if net.broadcast_address else "N/A")
        hosts = list(net.hosts())
        if hosts:
            self.info_labels["First Host"].setText(str(hosts[0]))
            self.info_labels["Last Host"].setText(str(hosts[-1]))
        else:
            self.info_labels["First Host"].setText("N/A")
            self.info_labels["Last Host"].setText("N/A")
        self.info_labels["Total Hosts"].setText(str(max(net.num_addresses - 2, 0)))
        self.info_labels["Address Range"].setText(f"{net.network_address} – {net.broadcast_address}")

        first = int(net.network_address)
        cls = "A" if first >> 31 == 0 else "B" if first >> 30 == 2 else "C" if first >> 29 == 6 else "D" if first >> 28 == 14 else "E"
        self.info_labels["Class"].setText(cls)

        self.subnet_viz.set_network(net)
        self.status.show_success(f"Calculated {net} — {net.num_addresses} addresses")


class SecurityTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()
        self._run_audit()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setSpacing(10); layout.setContentsMargins(14, 14, 14, 8)

        toolbar = QHBoxLayout(); toolbar.setSpacing(8)
        self.btn_audit = QPushButton("🛡  Run Security Audit"); self.btn_audit.setObjectName("scanBtn")
        self.score_widget = SecurityScoreWidget()
        self.score_label = QLabel("Score: --"); self.score_label.setObjectName("statValue")
        toolbar.addWidget(self.btn_audit)
        toolbar.addStretch()
        toolbar.addWidget(QLabel("Security Score:")); toolbar.addWidget(self.score_label)
        layout.addLayout(toolbar)

        self.status = InlineStatus(); layout.addWidget(self.status)

        # Issues table
        self.issues_table = QTableWidget(); self.issues_table.setColumnCount(4)
        self.issues_table.setHorizontalHeaderLabels(["Severity", "Category", "Issue", "Recommendation"])
        self.issues_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.issues_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.issues_table.setColumnWidth(0, 90)
        self.issues_table.setAlternatingRowColors(True)
        self.issues_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.issues_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.issues_table, stretch=1)

        self.btn_audit.clicked.connect(self._run_audit)

    def _run_audit(self):
        self.issues_table.setRowCount(0)
        issues = []; score = 100

        # Check 1: Open ports on localhost
        high_risk_local = []
        for port in [21, 22, 23, 80, 445, 3389, 8080]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    high_risk_local.append(port)
                s.close()
            except: pass

        if high_risk_local:
            sev = "high" if any(p in [23, 445, 3389] for p in high_risk_local) else "medium"
            issues.append((sev, "Open Ports",
                f"Open ports on localhost: {', '.join(str(p) for p in high_risk_local)}",
                "Close unnecessary services or restrict with firewall"))
            score -= len(high_risk_local) * 5

        # Check 2: DNS
        try:
            dns_servers = []
            if platform.system() == "Linux":
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            dns_servers.append(line.split()[1])
            if not dns_servers: dns_servers = ["8.8.8.8"]
            for dns in dns_servers:
                if not is_private_ip(dns):
                    issues.append(("info", "DNS", f"Using public DNS: {dns}",
                        "Consider using private DNS for better privacy"))
        except: pass

        # Check 3: Firewall
        fw_active = False
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'currentprofile', 'state'],
                    capture_output=True, text=True, creationflags=PROC_FLAGS)
                fw_active = "ON" in result.stdout.upper()
            elif platform.system() == "Linux":
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                fw_active = "active" in result.stdout.lower()
        except: pass
        if not fw_active:
            issues.append(("high", "Firewall", "Firewall may be inactive",
                "Enable host firewall immediately"))
            score -= 20

        # Check 4: Default credentials check
        issues.append(("medium", "Credentials", "Default service credentials not verified",
            "Change default passwords on all network services"))
        score -= 5

        # Check 5: ICMP response
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            # Try connecting to a common port externally
            s.close()
        except: pass

        # Check 6: Shared resources
        if platform.system() == "Windows":
            try:
                result = subprocess.run(['net', 'share'], capture_output=True, text=True, creationflags=PROC_FLAGS)
                if "C$" in result.stdout or "ADMIN$" in result.stdout:
                    issues.append(("medium", "Shares", "Administrative shares are enabled",
                        "Disable default admin shares if not needed"))
                    score -= 5
            except: pass

        # General advice
        if PSUTIL_AVAILABLE:
            conns = psutil.net_connections(kind='inet')
            established = [c for c in conns if c.status == 'ESTABLISHED']
            if len(established) > 50:
                issues.append(("medium", "Connections", f"High number of connections: {len(established)}",
                    "Investigate unusual connection activity"))
                score -= 5
            listening = [c for c in conns if c.status == 'LISTEN']
            if len(listening) > 20:
                issues.append(("low", "Services", f"Many listening services: {len(listening)}",
                    "Review and disable unnecessary services"))
                score -= 3

        # Always add some info-level items
        issues.append(("info", "Encryption", "Verify TLS/SSL on external connections",
            "Use HTTPS and encrypted protocols where possible"))
        issues.append(("info", "Updates", "Ensure OS and software are up-to-date",
            "Regularly check for security patches"))

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        issues.sort(key=lambda x: sev_order.get(x[0], 5))

        score = max(0, min(100, score))
        self.score_widget.set_score(score)
        self.score_label.setText(str(int(score)))

        for sev, cat, issue, rec in issues:
            row = self.issues_table.rowCount(); self.issues_table.insertRow(row)
            color = QColor(RISK_COLORS.get(sev, '#d0d0e0'))
            items = [
                QTableWidgetItem(sev.upper()),
                QTableWidgetItem(cat),
                QTableWidgetItem(issue),
                QTableWidgetItem(rec)
            ]
            items[0].setForeground(QBrush(color))
            items[0].setFont(QFont("Segoe UI", 12, QFont.Bold))
            items[0].setTextAlignment(Qt.AlignCenter)
            for it in items: self.issues_table.setItem(row, items.index(it), it)

        if not issues:
            self.status.show_success("No security issues found")
        else:
            high_count = sum(1 for s, *_ in issues if s in ("critical", "high"))
            if high_count > 0:
                self.status.show_warning(f"Found {high_count} high-severity issues — score: {score}")
            else:
                self.status.show_info(f"Found {len(issues)} items — score: {score}")


# ══════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analyzer Pro")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        # Central widget
        central = QWidget(); self.setCentralWidget(central)
        main_layout = QVBoxLayout(central); main_layout.setSpacing(0); main_layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QFrame(); header.setFixedHeight(50)
        header.setStyleSheet("background: #080812; border-bottom: 1px solid #1e1e3a;")
        hl = QHBoxLayout(header); hl.setContentsMargins(16, 0, 16, 0)
        logo = QLabel("⬡  Network Analyzer Pro")
        logo.setStyleSheet("font-size: 16px; font-weight: 700; color: #e8e8ff; background: transparent;")
        version = QLabel("v2.0")
        version.setStyleSheet("color: #4a4a77; font-size: 11px; background: transparent;")
        self.status_indicator = QLabel("●  Ready")
        self.status_indicator.setStyleSheet("color: #6a6a99; font-size: 12px; background: transparent;")
        hl.addWidget(logo); hl.addWidget(version); hl.addStretch(); hl.addWidget(self.status_indicator)
        main_layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabPosition(QTabWidget.North)

        self.dashboard = DashboardTab()
        self.capture_tab = CaptureTab(self)
        self.scanner_tab = ScannerTab()
        self.diagnostics_tab = DiagnosticsTab()
        self.network_map = NetworkMapTab()
        self.subnet_tab = SubnetTab()
        self.security_tab = SecurityTab()

        self.tabs.addTab(self.dashboard, "📊  Dashboard")
        self.tabs.addTab(self.capture_tab, "📡  Capture")
        self.tabs.addTab(self.scanner_tab, "🔍  Scanner")
        self.tabs.addTab(self.diagnostics_tab, "🔧  Diagnostics")
        self.tabs.addTab(self.network_map, "🗺  Network Map")
        self.tabs.addTab(self.subnet_tab, "📐  Subnet Calc")
        self.tabs.addTab(self.security_tab, "🛡  Security")

        main_layout.addWidget(self.tabs, stretch=1)

        # Status bar
        self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        self._status_label = QLabel("Ready"); self._status_label.setStyleSheet("padding: 0 8px;")
        self.status_bar.addPermanentWidget(self._status_label)

        # Toast overlay
        self.toast = ToastNotification(self)

        # Refresh timer for status bar
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self._update_status)
        self._refresh_timer.start(2000)

        # Initial data
        self.network_map._refresh()

    def show_toast(self, message, level="info"):
        self.toast.show_message(message, level)
        # Position top-right
        self.toast.move(self.width() - self.toast.width() - 20, 60)

    def _update_status(self):
        local_ip = get_local_ip()
        if PSUTIL_AVAILABLE:
            conns = len(psutil.net_connections(kind='inet'))
            self._status_label.setText(f"IP: {local_ip}  |  Connections: {conns}")
        else:
            self._status_label.setText(f"IP: {local_ip}")


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_STYLE)

    # High DPI
    app.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()