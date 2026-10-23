"""Qt-painted traffic charts; refresh happens at the configured timer interval."""

from PySide6.QtCore import QRectF
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget


class StatisticsView(QWidget):
    def __init__(self):
        super().__init__()
        self.stats = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 13, 16, 8)
        layout.setSpacing(9)
        metrics = QHBoxLayout()
        metrics.setSpacing(9)
        layout.addLayout(metrics)
        self.metric_values = {}
        for key, title in (("packets", "PACKETS"), ("bytes", "BYTES"),
                           ("packet_rate", "AVG PACKETS / S"),
                           ("byte_rate", "AVG BYTES / S"), ("flows", "TCP FLOWS")):
            card = QFrame()
            card.setObjectName("metricCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 8, 12, 8)
            card_layout.setSpacing(3)
            label = QLabel(title)
            label.setObjectName("metricLabel")
            value = QLabel("0")
            value.setObjectName("metricValue")
            card_layout.addWidget(label)
            card_layout.addWidget(value)
            metrics.addWidget(card, 1)
            self.metric_values[key] = value
        layout.addStretch()

    def refresh(self, stats, connections):
        self.stats = stats
        seconds = max(1, max(stats.timeline) - min(stats.timeline) + 1) if stats.timeline else 1
        values = {
            "packets": f"{stats.total_packets:,}",
            "bytes": f"{stats.total_bytes:,}",
            "packet_rate": f"{stats.total_packets / seconds:,.1f}",
            "byte_rate": f"{stats.total_bytes / seconds:,.1f}",
            "flows": f"{connections:,}",
        }
        for key, value in values.items():
            self.metric_values[key].setText(value)
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        left, width = 16, max(100, self.width() - 32)
        top = 93
        available = max(100, self.height() - top - 18)
        traffic_height = max(100, int(available * 0.48))
        lower_top = top + traffic_height + 10
        lower_height = max(70, self.height() - lower_top - 18)
        self._card(painter, left, top, width, traffic_height)
        gap = 10
        third = (width - 2 * gap) // 3
        for column in range(3):
            self._card(painter, left + column * (third + gap), lower_top, third, lower_height)
        if self.stats:
            self._traffic(painter, left, top, width, traffic_height)
            self._bars(painter, "Protocol distribution · packets",
                       self.stats.protocols.most_common(5), left, lower_top, third, lower_height, "#62D6C3")
            self._bars(painter, "Top talkers · bytes",
                       self.stats.host_bytes.most_common(5), left + third + gap, lower_top,
                       third, lower_height, "#69B9F2")
            self._bars(painter, "Top ports · packets",
                       self.stats.top_ports(5), left + 2 * (third + gap), lower_top,
                       third, lower_height, "#B996F5")
        painter.end()

    def _card(self, painter, left, top, width, height):
        painter.setPen(QPen(QColor("#293241")))
        painter.setBrush(QColor("#171E28"))
        painter.drawRoundedRect(QRectF(left, top, width, height), 7, 7)

    def _title(self, painter, title, left, top):
        painter.setPen(QColor("#D8E5F1"))
        painter.drawText(left + 13, top + 22, title)

    def _traffic(self, painter, left, top, width, height):
        self._title(painter, "Traffic over time · bytes/s · last 60 s", left, top)
        timeline = self.stats.timeline
        if not timeline:
            return
        latest = max(timeline)
        values = [timeline.get(second, 0) for second in range(latest - 59, latest + 1)]
        maximum = max(values) or 1
        graph_left, graph_right = left + 16, left + width - 18
        graph_top, graph_bottom = top + 38, top + height - 17
        painter.setPen(QPen(QColor("#293241"), 1))
        for fraction in (0, 0.5, 1):
            y = graph_bottom - fraction * (graph_bottom - graph_top)
            painter.drawLine(int(graph_left), int(y), int(graph_right), int(y))
        painter.setPen(QPen(QColor("#50B8E7"), 2))
        for i in range(1, len(values)):
            x1 = graph_left + (i - 1) * (graph_right - graph_left) / 59
            x2 = graph_left + i * (graph_right - graph_left) / 59
            y1 = graph_bottom - values[i - 1] / maximum * (graph_bottom - graph_top)
            y2 = graph_bottom - values[i] / maximum * (graph_bottom - graph_top)
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))
        painter.setPen(QColor("#95A7BB"))
        painter.drawText(left + width - 116, top + 22, f"peak {maximum:,}")

    def _bars(self, painter, title, pairs, left, top, width, height, color):
        self._title(painter, title, left, top)
        if not pairs:
            return
        maximum = max(value for _, value in pairs) or 1
        row_height = max(18, min(27, (height - 38) // len(pairs)))
        bar_left = left + min(115, max(85, width - 105))
        bar_room = max(25, width - (bar_left - left) - 62)
        for i, (label, value) in enumerate(pairs):
            y = top + 35 + i * row_height
            painter.setPen(QColor("#B9C9D9"))
            painter.drawText(left + 12, y + 11, str(label)[:14])
            painter.setPen(QColor("#293241"))
            painter.setBrush(QColor("#253140"))
            painter.drawRoundedRect(QRectF(bar_left, y + 2, bar_room, 10), 3, 3)
            bar_width = max(1, int(bar_room * value / maximum))
            painter.setPen(QColor(color))
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(QRectF(bar_left, y + 2, bar_width, 10), 3, 3)
            painter.setPen(QColor("#B9C9D9"))
            painter.drawText(bar_left + bar_room + 7, y + 11, f"{value:,}")
