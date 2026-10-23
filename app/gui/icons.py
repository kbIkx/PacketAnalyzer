"""Small, original outline icons rendered by Qt from embedded SVG."""

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer


PATHS = {
    "capture": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 1v3m0 16v3M1 12h3m16 0h3"/>',
    "statistics": '<path d="M3 21h18M5 17v-5h3v5m3 0V5h3v12m3 0V9h3v8"/>',
    "connections": '<circle cx="5" cy="6" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M7 7l4 9m6-9-4 9M7 6h10"/>',
    "files": '<path d="M5 2h9l5 5v15H5zM14 2v5h5M8 12h8m-8 4h8"/>',
    "settings": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2" fill="#151B23"/><circle cx="16" cy="12" r="2" fill="#151B23"/><circle cx="11" cy="18" r="2" fill="#151B23"/>',
}


def icon(name, color="#95A7BB", size=20):
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
           f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.8" '
           f'stroke-linecap="round" stroke-linejoin="round">{PATHS[name]}</svg>')
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)
