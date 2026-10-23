"""Capture the real GUI with synthetic packets only (no private traffic)."""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFontDatabase
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether

from app.gui.main_window import MainWindow
from app.gui.styles import STYLE
from app.parser import parse_packet


def main():
    app = QApplication([])
    for font in ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/consola.ttf"):
        QFontDatabase.addApplicationFont(font)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.resize(1360, 850)
    window.interfaces.clear()
    window.interfaces.addItem("Demo interface (synthetic packets)", "demo")
    packets = []
    ethernet = lambda: Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    for i in range(12):
        packets.extend((
            ethernet()/IP(src=f"192.0.2.{i + 1}", dst="198.51.100.20")/TCP(sport=50000 + i, dport=443, flags="S"),
            ethernet()/IP(src="198.51.100.20", dst=f"192.0.2.{i + 1}")/TCP(sport=443, dport=50000 + i, flags="SA"),
            ethernet()/IP(src=f"192.0.2.{i + 1}", dst="203.0.113.53")/UDP(sport=51000 + i, dport=53),
        ))
    packets.extend((ethernet()/IP(src="203.0.113.2", dst="192.0.2.1")/ICMP(),
                    ethernet()/ARP(psrc="192.0.2.1", pdst="192.0.2.2")))
    for packet in packets:
        window.events.put((window.generation, "packet", packet, parse_packet(packet)))
    window._drain()
    window.table.selectRow(1)
    window.show()
    app.processEvents()
    target = Path(__file__).with_name("main-window.png")
    if not window.grab().save(str(target)):
        raise RuntimeError("Could not save screenshot")
    window.close()
    print(target)


if __name__ == "__main__":
    main()
