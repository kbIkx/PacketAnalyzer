"""Qt GUI. Capture and file workers communicate only through a bounded queue."""

import csv
import ipaddress
from datetime import datetime
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread

from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QSpinBox, QSplitter, QTabWidget, QTableView, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget)

from app.capture import PacketCapture, available_interfaces
from app.connections import ConnectionTracker
from app.filters import PacketFilter
from app.gui.packet_table import PacketProxy, PacketRow, PacketTableModel
from app.gui.statistics_view import StatisticsView
from app.parser import parse_packet
from app.pcap import iter_packets, save_packets
from app.statistics import TrafficStatistics


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PacketAnalyzer")
        self.resize(1360, 850)
        self.setMinimumSize(1050, 650)
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
        self._build()
        self.refresh_interfaces()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._drain)
        self.timer.start(50)
        self.chart_timer = QTimer(self)
        self.chart_timer.timeout.connect(self._refresh_summary)
        self.chart_timer.start(int(self.settings.value("chart_interval", 1)) * 1000)

    def _button(self, label, callback, object_name=""):
        button = QPushButton(label)
        if object_name:
            button.setObjectName(object_name)
        button.clicked.connect(callback)
        return button

    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        bar = QHBoxLayout()
        layout.addLayout(bar)
        bar.addWidget(QLabel("Interface"))
        self.interfaces = QComboBox()
        self.interfaces.setMinimumWidth(290)
        bar.addWidget(self.interfaces, 1)
        bar.addWidget(self._button("Refresh", self.refresh_interfaces))
        self.start_button = self._button("Start Capture", self.start_capture, "start")
        self.stop_button = self._button("Stop Capture", self.stop_capture, "stop")
        self.stop_button.setEnabled(False)
        bar.addWidget(self.start_button)
        bar.addWidget(self.stop_button)
        bar.addWidget(self._button("Clear", self.clear))
        bar.addWidget(self._button("Open PCAP", self.open_pcap))
        bar.addWidget(self._button("Save PCAP", self.save_pcap))
        bar.addWidget(self._button("Export CSV", self.export_csv))

        options = QHBoxLayout()
        layout.addLayout(options)
        self.status = QLabel("Idle")
        self.status.setObjectName("status")
        options.addWidget(self.status, 1)
        self.pause = QCheckBox("Pause display")
        self.pause.toggled.connect(self._toggle_pause)
        options.addWidget(self.pause)
        self.scroll = QCheckBox("Auto scroll")
        self.scroll.setChecked(str(self.settings.value("auto_scroll", "true")).lower() == "true")
        options.addWidget(self.scroll)
        options.addWidget(QLabel("Memory limit"))
        self.limit = QSpinBox()
        self.limit.setRange(100, 100000)
        self.limit.setSingleStep(1000)
        self.limit.setValue(self.maximum)
        self.limit.valueChanged.connect(self._set_limit)
        options.addWidget(self.limit)
        options.addWidget(QLabel("Charts every"))
        self.chart_interval = QSpinBox()
        self.chart_interval.setRange(1, 10)
        self.chart_interval.setSuffix(" s")
        self.chart_interval.setValue(max(1, min(10, int(self.settings.value("chart_interval", 1)))))
        self.chart_interval.valueChanged.connect(lambda value: self.chart_timer.setInterval(value * 1000)
                                                 if hasattr(self, "chart_timer") else None)
        options.addWidget(self.chart_interval)

        filters = QGridLayout()
        layout.addLayout(filters)
        self.protocol = QComboBox()
        self.protocol.addItems(("All protocols", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IPv6", "OTHER"))
        filters.addWidget(QLabel("Display filter"), 0, 0)
        filters.addWidget(self.protocol, 0, 1)
        self.inputs = {}
        specs = (("Source IP", "source"), ("Destination IP", "destination"),
                 ("Either IP", "host"), ("Source port", "source_port"),
                 ("Destination port", "destination_port"), ("Either port", "port"),
                 ("Text", "text"))
        for i, (label, name) in enumerate(specs):
            row = 0 if i < 3 else 1
            col = 2 + (i if row == 0 else i - 3) * 2
            filters.addWidget(QLabel(label), row, col)
            field = QLineEdit()
            field.setPlaceholderText(label)
            field.returnPressed.connect(self.apply_filters)
            filters.addWidget(field, row, col + 1)
            self.inputs[name] = field
        filters.addWidget(self._button("Apply", self.apply_filters), 1, 0)
        filters.addWidget(self._button("Reset", self.reset_filters), 1, 1)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, 1)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        for col, width in enumerate((65, 120, 185, 185, 95, 80)):
            self.table.setColumnWidth(col, width)
        self.table.selectionModel().currentRowChanged.connect(self._show_packet)
        splitter.addWidget(self.table)
        tabs = QTabWidget()
        splitter.addWidget(tabs)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setFontFamily("Consolas")
        tabs.addTab(self.details, "Packet details + hex")
        self.statistics_view = StatisticsView()
        tabs.addTab(self.statistics_view, "Statistics")
        self.connections = QTableWidget(0, 9)
        self.connections.setHorizontalHeaderLabels(("Source", "Src port", "Destination", "Dst port",
            "Protocol", "Packets", "Bytes", "First / Last", "Observed flags"))
        self.connections.horizontalHeader().setStretchLastSection(True)
        tabs.addTab(self.connections, "TCP flows")
        splitter.setSizes((510, 270))
        self.count_label = QLabel("0 shown / 0 retained / 0 observed")
        layout.addWidget(self.count_label)

    def refresh_interfaces(self):
        previous = self.interfaces.currentData() or self.settings.value("interface", "")
        self.interfaces.clear()
        try:
            for label, iface in available_interfaces():
                self.interfaces.addItem(label, iface.name)
        except Exception as exc:
            self.status.setText(f"Interface discovery failed: {exc}")
        index = self.interfaces.findData(previous)
        if index >= 0:
            self.interfaces.setCurrentIndex(index)
        if not self.interfaces.count():
            self.status.setText("No network interfaces found. Install Npcap for live capture.")

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
        self.status.setText(f"Capturing on {interface}")

    def stop_capture(self):
        if self.capture:
            self.capture.stop(wait=False)
        self.stop_button.setEnabled(False)
        self.status.setText("Stopping capture…")

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
        packet, info = row.packet, row.info
        fields = [f"Packet #{row.number} · {info.protocol} · {info.size} bytes",
                  f"Source: {info.source}    Destination: {info.destination}"]
        for label, value in (("Source MAC", info.source_mac), ("Destination MAC", info.destination_mac),
                             ("TTL / Hop limit", info.ttl), ("Source port", info.source_port),
                             ("Destination port", info.destination_port), ("TCP flags", info.flags)):
            if value not in (None, ""):
                fields.append(f"{label}: {value}")
        raw = bytes(packet)
        hex_lines = [f"{offset:08x}  " + " ".join(f"{byte:02x}" for byte in raw[offset:offset + 16])
                     for offset in range(0, len(raw), 16)]
        self.details.setPlainText("\n".join(fields) + "\n\nLayers\n" + packet.show(dump=True)
                                  + "\nHex\n" + "\n".join(hex_lines))

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
                self.status.setText(f"Error: {event[2]}")
                if self.capture:
                    self.capture.stop(wait=False)
                self.stop_button.setEnabled(False)
                self.start_button.setEnabled(True)
            elif event[1] == "done":
                self.status.setText(f"Loaded {event[2]:,} packets from PCAP")
            elif event[1] == "saved":
                self.status.setText(f"Saved {event[2]:,} retained packets to {event[3]}")
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
                self.status.setText("Idle")

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
        self.count_label.setText(f"{self.proxy.rowCount():,} shown / {self.model.rowCount():,} retained / "
                                 f"{self.stats.total_packets:,} observed · {self.dropped:,} dropped from UI queue")

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
        self.status.setText(f"Loading {Path(path).name}…")

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
            self.status.setText(f"Saving {len(packets):,} retained packets…")

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
            self.status.setText(f"Exported {self.proxy.rowCount():,} displayed rows to CSV")
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
        super().closeEvent(event)
