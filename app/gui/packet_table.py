from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont

from app.filters import PacketFilter


@dataclass
class PacketRow:
    number: int
    packet: object
    info: object


class PacketTableModel(QAbstractTableModel):
    HEADERS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
    ACCENTS = {"TCP": "#69B9F2", "UDP": "#62D6C3", "ICMP": "#E5B662",
               "ICMPv6": "#E5B662", "ARP": "#B996F5"}

    def __init__(self, maximum=10000):
        super().__init__()
        self.rows = []
        self.maximum = maximum

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        info = row.info
        values = (row.number, datetime.fromtimestamp(info.timestamp).strftime("%H:%M:%S.%f")[:-3],
                  info.source, info.destination, info.protocol, info.size, info.info)
        if role == Qt.ItemDataRole.DisplayRole:
            return str(values[index.column()])
        if role == Qt.ItemDataRole.UserRole:
            return (row.number, info.timestamp, info.source, info.destination,
                    info.protocol, info.size, info.info)[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole:
            return QColor(self.ACCENTS.get(info.protocol, "#AEBED0") if index.column() == 4 else "#DCE6F1")
        if role == Qt.ItemDataRole.ToolTipRole:
            return str(values[index.column()])
        if role == Qt.ItemDataRole.FontRole:
            font = QFont("Consolas" if index.column() in (0, 1, 2, 3, 5) else "Segoe UI", 9)
            font.setBold(index.column() == 4)
            return font
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (0, 5):
            return Qt.AlignmentFlag.AlignCenter
        return None

    def append(self, rows):
        if not rows:
            return
        overflow = max(0, len(self.rows) + len(rows) - self.maximum)
        if overflow:
            self.beginResetModel()
            self.rows = (self.rows + rows)[-self.maximum:]
            self.endResetModel()
        else:
            first = len(self.rows)
            self.beginInsertRows(QModelIndex(), first, first + len(rows) - 1)
            self.rows.extend(rows)
            self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.rows.clear()
        self.endResetModel()

    def set_maximum(self, maximum):
        self.beginResetModel()
        self.maximum = maximum
        self.rows = self.rows[-maximum:]
        self.endResetModel()


class PacketProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.packet_filter = PacketFilter()
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def filterAcceptsRow(self, source_row, parent):
        return self.packet_filter.matches(self.sourceModel().rows[source_row].info)

    def set_packet_filter(self, packet_filter):
        if hasattr(self, "beginFilterChange"):
            self.beginFilterChange()
        self.packet_filter = packet_filter
        if hasattr(self, "endFilterChange"):
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            self.invalidateFilter()
