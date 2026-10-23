from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class StatisticsView(QWidget):
    """Three lightweight charts, repainted on the one-second UI timer."""

    def __init__(self):
        super().__init__()
        self.stats = None
        self.summary = QLabel("No packets")
        self.summary.setMinimumHeight(38)
        self.top_ports = QLabel("Top ports: —")
        layout = QVBoxLayout(self)
        layout.addWidget(self.summary)
        layout.addWidget(self.top_ports)
        layout.addStretch()

    def refresh(self, stats, connections):
        self.stats = stats
        if stats.total_packets:
            seconds = max(1, max(stats.timeline) - min(stats.timeline) + 1)
            self.summary.setText(
                f"Packets: {stats.total_packets:,}    Bytes: {stats.total_bytes:,}    "
                f"Avg: {stats.total_packets / seconds:.1f} pkt/s    "
                f"{stats.total_bytes / seconds:.1f} B/s    TCP flows: {connections}"
            )
        else:
            self.summary.setText("No packets")
        self.top_ports.setText("Top ports by packets: " + ", ".join(
            f"{port} ({count:,})" for port, count in stats.top_ports(6)) if stats.total_packets else "Top ports: —")
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self.stats:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        left, width = 24, max(100, self.width() - 48)
        top = 70
        height = max(100, (self.height() - top - 30) // 3)
        self._traffic(painter, left, top, width, height)
        self._bars(painter, "Protocol distribution · packets",
                   self.stats.protocols.most_common(6), left, top + height, width, height, "#63c9ba")
        self._bars(painter, "Top talkers · bytes (both directions)",
                   self.stats.host_bytes.most_common(6), left, top + 2 * height, width, height, "#84a6eb")
        painter.end()

    def _title(self, painter, title, left, top):
        painter.setPen(QColor("#dce6f4"))
        painter.drawText(left, top + 16, title)

    def _traffic(self, painter, left, top, width, height):
        self._title(painter, "Traffic over time · bytes/s", left, top)
        timeline = self.stats.timeline
        if not timeline:
            return
        latest = max(timeline)
        values = [timeline.get(second, 0) for second in range(latest - 59, latest + 1)]
        maximum = max(values) or 1
        graph_top, graph_bottom = top + 28, top + height - 14
        painter.setPen(QPen(QColor("#63c9ba"), 2))
        for i in range(1, len(values)):
            x1 = left + (i - 1) * width / 59
            x2 = left + i * width / 59
            y1 = graph_bottom - values[i - 1] / maximum * (graph_bottom - graph_top)
            y2 = graph_bottom - values[i] / maximum * (graph_bottom - graph_top)
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))
        painter.setPen(QColor("#92a0b3"))
        painter.drawText(left + width - 100, top + 16, f"peak {maximum:,}")

    def _bars(self, painter, title, pairs, left, top, width, height, color):
        self._title(painter, title, left, top)
        if not pairs:
            return
        maximum = max(value for _, value in pairs) or 1
        space = max(14, (height - 28) // max(1, len(pairs)))
        for i, (label, value) in enumerate(pairs):
            y = top + 29 + i * space
            painter.setPen(QColor("#c5d0df"))
            painter.drawText(left, y + 11, str(label)[:22])
            bar_x = left + min(210, width // 3)
            bar_width = max(1, int((width - (bar_x - left) - 90) * value / maximum))
            painter.fillRect(bar_x, y, bar_width, 13, QColor(color))
            painter.drawText(bar_x + bar_width + 6, y + 11, f"{value:,}")
