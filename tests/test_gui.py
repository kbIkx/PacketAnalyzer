import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QFileDialog
from scapy.all import Ether, IP, TCP

from app.gui.main_window import MainWindow
from app.parser import parse_packet
from app.pcap import read_packets, save_packets


def test_gui_table_filter_pause_and_pcap_io(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1234, dport=443)
    try:
        window.events.put((window.generation, "packet", packet, parse_packet(packet)))
        window._drain()
        assert window.model.rowCount() == window.proxy.rowCount() == 1
        window.table.selectRow(0)
        assert window.details.tree.topLevelItemCount() >= 2
        assert window.details.hex.toPlainText().startswith("00000000")
        window._set_page(1)
        assert window.workspace_tabs.currentIndex() == 1
        window._set_page(0)
        window.inputs["source"].setText("203.0.113.1")
        window.apply_filters()
        assert window.proxy.rowCount() == 0
        window.reset_filters()
        assert window.proxy.rowCount() == 1

        window.pause.setChecked(True)
        window.events.put((window.generation, "packet", packet, parse_packet(packet)))
        window._drain()
        assert window.model.rowCount() == 1
        window.pause.setChecked(False)
        assert window.model.rowCount() == 2

        source = tmp_path / "source.pcap"
        target = tmp_path / "export.pcap"
        save_packets([packet], source)
        monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args: (str(source), ""))
        window.open_pcap()
        deadline = time.monotonic() + 5
        while window.model.rowCount() != 1 and time.monotonic() < deadline:
            app.processEvents()
            window._drain()
            time.sleep(0.01)
        assert window.model.rowCount() == 1

        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args: (str(target), ""))
        window.save_pcap()
        deadline = time.monotonic() + 5
        while not target.exists() and time.monotonic() < deadline:
            app.processEvents()
            window._drain()
            time.sleep(0.01)
        assert len(read_packets(target)) == 1
    finally:
        window.close()
