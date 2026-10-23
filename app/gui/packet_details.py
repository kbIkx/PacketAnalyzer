"""Protocol tree and offset/hex/ASCII inspection for the selected packet."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPlainTextEdit,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)


class PacketDetails(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        heading = QFrame()
        heading.setObjectName("sectionHeading")
        top = QHBoxLayout(heading)
        top.setContentsMargins(15, 5, 15, 5)
        title = QLabel("PACKET INSPECTOR")
        title.setObjectName("eyebrow")
        top.addWidget(title)
        top.addStretch()
        self.summary = QLabel("Select a packet to inspect its layers and bytes")
        self.summary.setObjectName("muted")
        top.addWidget(self.summary)
        layout.addWidget(heading)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        layout.addWidget(self.splitter, 1)
        self.tree = QTreeWidget()
        self.tree.setObjectName("protocolTree")
        self.tree.setHeaderLabels(("Protocol / Field", "Value"))
        self.tree.setColumnWidth(0, 185)
        self.tree.setAlternatingRowColors(True)
        self.splitter.addWidget(self.tree)
        self.hex = QPlainTextEdit()
        self.hex.setObjectName("hexView")
        self.hex.setReadOnly(True)
        self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex.setPlaceholderText("Raw packet bytes appear here")
        self.splitter.addWidget(self.hex)
        self.splitter.setSizes((440, 550))

    def clear(self):
        self.tree.clear()
        self.hex.clear()
        self.summary.setText("Select a packet to inspect its layers and bytes")

    def show_packet(self, packet, info, number):
        self.tree.clear()
        self.summary.setText(f"#{number:,}  ·  {info.protocol}  ·  {info.size:,} bytes")
        layer = packet
        while layer and layer.name != "NoPayload":
            parent = QTreeWidgetItem((layer.name, ""))
            self.tree.addTopLevelItem(parent)
            for key, value in layer.fields.items():
                if isinstance(value, bytes):
                    display = f"{len(value)} bytes"
                else:
                    display = str(value)
                child = QTreeWidgetItem((str(key), display))
                child.setToolTip(1, display)
                parent.addChild(child)
            parent.setExpanded(True)
            layer = layer.payload
        raw = bytes(packet)
        lines = []
        for offset in range(0, len(raw), 16):
            chunk = raw[offset:offset + 16]
            hex_text = " ".join(f"{byte:02X}" for byte in chunk)
            ascii_text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            lines.append(f"{offset:08X}   {hex_text:<47}   {ascii_text}")
        self.hex.setPlainText("\n".join(lines))
        self.hex.moveCursor(QTextCursor.MoveOperation.Start)
