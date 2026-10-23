"""Qt GUI. Capture and file workers communicate only through a bounded queue."""

import csv
import ipaddress
from datetime import datetime
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread

from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMenu, QMessageBox, QTableWidgetItem

from app.capture import PacketCapture, available_interfaces
from app.connections import ConnectionTracker
from app.filters import PacketFilter
from app.gui.packet_table import PacketProxy, PacketRow, PacketTableModel
from app.gui.layout import PAGES, build_window
from app.gui.icons import icon
from app.gui.statistics_view import StatisticsView
from app.parser import parse_packet
from app.pcap import iter_packets, save_packets
from app.statistics import TrafficStatistics


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PacketAnalyzer")
        self.resize(1360, 850)
        self.setMinimumSize(800, 460)
        self.settings = QSettings("PacketAnalyzer", "PacketAnalyzer")
        self.maximum = max(100, min(100000, int(self.settings.value("maximum", 10000))))
        self.events = Queue(maxsize=3000)
        self.generation = 0
        self.file_cancel = Event()
        self.capture = None
        self.dropped = 0
        self.sequence = 0
        self.pending_rows = []
        self.stats = TrafficStatistics()
        self.tracker = ConnectionTracker()
        self.model = PacketTableModel(self.maximum)
        self.proxy = PacketProxy()
        self.proxy.setSourceModel(self.model)
        build_window(self)
        self.refresh_interfaces()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._drain)
        self.timer.start(50)
        self.chart_timer = QTimer(self)
        self.chart_timer.timeout.connect(self._refresh_summary)
        self.chart_timer.start(int(self.settings.value("chart_interval", 1)) * 1000)

    def _set_status(self, message, tone="idle"):
        self.status.setText(message)
        self.status.setToolTip(message)
        for widget in (self.status, self.status_dot):
            widget.setProperty("tone", tone)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def _toggle_filters(self, shown):
        self.filter_body.setVisible(shown)
        self.filter_toggle.setText("Fewer filters" if shown else "More filters")

    def _set_page(self, index):
        self.workspace_tabs.setCurrentIndex(index)
        self.page_title.setText(PAGES[index][0])
        self.page_subtitle.setText(PAGES[index][1])
        for number, button in enumerate(self.nav_buttons):
            button.setChecked(number == index)
            button.setIcon(icon(PAGES[number][2], "#50B8E7" if number == index else "#95A7BB"))

    def _packet_menu(self, position):
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        info = self.model.rows[self.proxy.mapToSource(index).row()].info
        menu = QMenu(self)
        for label, value in (("Copy source", info.source), ("Copy destination", info.destination),
                             ("Copy summary", info.info)):
            action = menu.addAction(label)
            action.triggered.connect(lambda checked=False, text=value: QApplication.clipboard().setText(str(text)))
        menu.exec(self.table.viewport().mapToGlobal(position))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not hasattr(self, "sidebar"):
            return
        compact = self.width() < 1000
        self.sidebar.setFixedWidth(60 if compact else 188)
        for widget in (self.brand_label, self.brand_caption, self.sidebar_footer):
            widget.setVisible(not compact)
        self.page_subtitle.setVisible(not compact)
        self.header_count.setVisible(not compact)
        for button in self.nav_buttons:
            button.setFixedWidth(60 if compact else 188)
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly if compact
                                      else Qt.ToolButtonStyle.ToolButtonTextBesideIcon)

    def refresh_interfaces(self):
        previous = self.interfaces.currentData() or self.settings.value("interface", "")
        self.interfaces.clear()
        try:
            for label, iface in available_interfaces():
                self.interfaces.addItem(label, iface.name)
        except Exception as exc:
            self._set_status(f"Interface discovery failed: {exc}", "error")
        index = self.interfaces.findData(previous)
        if index >= 0:
            self.interfaces.setCurrentIndex(index)
        if not self.interfaces.count():
            self._set_status("No network interfaces found. Install Npcap for live capture.", "error")

    def start_capture(self):
        if self.capture and self.capture.running:
            return
        interface = self.interfaces.currentData()
        if not interface:
            QMessageBox.warning(self, "Capture", "Select a network interface. Check Npcap installation.")
            return
        self.file_cancel.set()
        self.generation += 1
        generation = self.generation
        self.capture = PacketCapture(interface)

        def on_packet(packet):
            try:
                self.events.put_nowait((generation, "packet", packet, parse_packet(packet)))
            except Full:
                self.dropped += 1
            except Exception as exc:
                self.events.put((generation, "error", str(exc)), timeout=1)

        def on_error(exc):
            try:
                self.events.put((generation, "error", str(exc)), timeout=1)
            except Full:
                pass

        self.capture.start(on_packet, on_error)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._set_status(f"Capturing on {interface}", "active")

    def stop_capture(self):
        if self.capture:
            self.capture.stop(wait=False)
        self.stop_button.setEnabled(False)
        self._set_status("Stopping capture…", "busy")

    def clear(self):
        self.model.clear()
        self.pending_rows.clear()
        self.stats = TrafficStatistics()
        self.tracker = ConnectionTracker()
        self.sequence = 0
        self.dropped = 0
        self.details.clear()
        self._refresh_summary()

    def _set_limit(self, value):
        self.model.set_maximum(value)
        self.pending_rows = self.pending_rows[-value:]
        self._refresh_summary()

    def _toggle_pause(self, paused):
        if not paused and self.pending_rows:
            self.model.append(self.pending_rows)
            self.pending_rows.clear()
            if self.scroll.isChecked():
                self.table.scrollToBottom()
            self._update_count()

    def _read_filter(self):
        values = {name: field.text().strip() or None for name, field in self.inputs.items()}
        for name in ("source", "destination", "host"):
            if values[name]:
                values[name] = str(ipaddress.ip_address(values[name]))
        for name in ("source_port", "destination_port", "port"):
            if values[name]:
                number = int(values[name])
                if not 0 <= number <= 65535:
                    raise ValueError(f"{name} must be between 0 and 65535")
                values[name] = number
        protocol = self.protocol.currentText()
        values["protocol"] = None if protocol == "All protocols" else protocol
        return PacketFilter(**values)

    def apply_filters(self):
        try:
            packet_filter = self._read_filter()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid display filter", str(exc))
            return
        self.proxy.set_packet_filter(packet_filter)
        self._refresh_summary()

    def reset_filters(self):
        self.protocol.setCurrentIndex(0)
        for field in self.inputs.values():
            field.clear()
        self.apply_filters()

    def _show_packet(self, current, previous):
        if not current.isValid():
            self.details.clear()
            return
        source = self.proxy.mapToSource(current)
        row = self.model.rows[source.row()]
        self.details.show_packet(row.packet, row.info, row.number)

    def _drain(self):
        batch = []
        for _ in range(250):
            try:
                event = self.events.get_nowait()
            except Empty:
                break
            if event[0] != self.generation:
                continue
            if event[1] == "packet":
                packet, info = event[2], event[3]
                self.sequence += 1
                batch.append(PacketRow(self.sequence, packet, info))
                self.stats.update(info)
                self.tracker.update(info)
            elif event[1] == "error":
                self._set_status(f"Error: {event[2]}", "error")
                if self.capture:
                    self.capture.stop(wait=False)
                self.stop_button.setEnabled(False)
                self.start_button.setEnabled(True)
            elif event[1] == "done":
                self._set_status(f"Loaded {event[2]:,} packets from PCAP", "success")
            elif event[1] == "saved":
                self._set_status(f"Saved {event[2]:,} retained packets to {event[3]}", "success")
        if batch:
            if self.pause.isChecked():
                self.pending_rows = (self.pending_rows + batch)[-self.model.maximum:]
            else:
                self.model.append(batch)
                if self.scroll.isChecked():
                    self.table.scrollToBottom()
            self._update_count()
        if self.capture and not self.capture.running and not self.start_button.isEnabled():
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            if self.status.text().startswith("Stopping"):
                self._set_status("Idle")

    def _refresh_summary(self):
        self._update_count()
        self.statistics_view.refresh(self.stats, len(self.tracker.connections))
        flows = sorted(self.tracker.all(), key=lambda flow: flow.bytes, reverse=True)[:200]
        self.connections.setRowCount(len(flows))
        for row, flow in enumerate(flows):
            first = datetime.fromtimestamp(flow.first_seen).strftime("%H:%M:%S")
            last = datetime.fromtimestamp(flow.last_seen).strftime("%H:%M:%S")
            values = (flow.source, flow.source_port, flow.destination, flow.destination_port,
                      "TCP", flow.packets, flow.bytes, f"{first} / {last}", flow.flags)
            for col, value in enumerate(values):
                self.connections.setItem(row, col, QTableWidgetItem(str(value)))

    def _update_count(self):
        summary = (f"{self.proxy.rowCount():,} shown  ·  {self.model.rowCount():,} retained  ·  "
                   f"{self.stats.total_packets:,} observed")
        if self.dropped:
            summary += f"  ·  {self.dropped:,} UI drops"
        self.count_label.setText(summary)
        self.count_label.setToolTip("Shown: display filter result. Retained: packets in memory. "
                                    "Observed: all processed packets. UI drops: bounded queue overflow.")
        self.header_count.setText(f"{self.stats.total_packets:,} packets")
        self.empty_label.setVisible(self.proxy.rowCount() == 0)

    def open_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP", self.settings.value("last_dir", ""),
                                              "PCAP files (*.pcap);;All files (*)")
        if not path:
            return
        self.stop_capture()
        self.file_cancel.set()
        self.file_cancel = Event()
        cancel = self.file_cancel
        self.generation += 1
        generation = self.generation
        self.clear()
        self.pause.setChecked(False)
        self.settings.setValue("last_dir", str(Path(path).parent))
        self._set_status(f"Loading {Path(path).name}…", "busy")

        def load():
            count = 0
            try:
                for packet in iter_packets(path):
                    if cancel.is_set():
                        return
                    event = (generation, "packet", packet, parse_packet(packet))
                    while not cancel.is_set():
                        try:
                            self.events.put(event, timeout=0.2)
                            break
                        except Full:
                            pass
                    count += 1
                self.events.put((generation, "done", count), timeout=2)
            except Exception as exc:
                try:
                    self.events.put((generation, "error", f"Cannot open PCAP: {exc}"), timeout=2)
                except Full:
                    pass

        Thread(target=load, name="pcap-reader", daemon=True).start()

    def save_pcap(self):
        if not self.model.rows:
            QMessageBox.information(self, "Save PCAP", "No retained packets to save.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save all retained packets (display filter ignored)",
                                              self.settings.value("last_dir", ""), "PCAP files (*.pcap)")
        if path:
            packets = [row.packet for row in (self.model.rows + self.pending_rows)[-self.model.maximum:]]
            generation = self.generation
            self.settings.setValue("last_dir", str(Path(path).parent))
            self._set_status(f"Saving {len(packets):,} retained packets…", "busy")

            def write():
                try:
                    save_packets(packets, path)
                    self.events.put((generation, "saved", len(packets), path), timeout=2)
                except Exception as exc:
                    try:
                        self.events.put((generation, "error", f"Save PCAP failed: {exc}"), timeout=2)
                    except Full:
                        pass

            Thread(target=write, name="pcap-writer", daemon=True).start()

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export displayed rows as CSV (metadata only)",
                                              self.settings.value("last_dir", ""), "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.writer(stream)
                writer.writerow(("Timestamp", "Source", "Destination", "Protocol", "Length",
                                 "Source port", "Destination port", "Info"))
                for index in range(self.proxy.rowCount()):
                    row = self.model.rows[self.proxy.mapToSource(self.proxy.index(index, 0)).row()]
                    info = row.info
                    writer.writerow((datetime.fromtimestamp(info.timestamp).isoformat(timespec="milliseconds"),
                                     info.source, info.destination, info.protocol, info.size,
                                     info.source_port, info.destination_port, info.info))
            self.settings.setValue("last_dir", str(Path(path).parent))
            self._set_status(f"Exported {self.proxy.rowCount():,} displayed rows to CSV", "success")
        except Exception as exc:
            QMessageBox.critical(self, "CSV export failed", str(exc))

    def closeEvent(self, event):
        self.file_cancel.set()
        if self.capture:
            self.capture.stop()
        self.settings.setValue("interface", self.interfaces.currentData() or "")
        self.settings.setValue("maximum", self.limit.value())
        self.settings.setValue("auto_scroll", self.scroll.isChecked())
        self.settings.setValue("chart_interval", self.chart_interval.value())
        self.settings.setValue("filters_open", self.filter_toggle.isChecked())
        self.settings.setValue("packet_splitter_v2", self.packet_splitter.saveState())
        self.settings.setValue("details_splitter_v2", self.details.splitter.saveState())
        super().closeEvent(event)
