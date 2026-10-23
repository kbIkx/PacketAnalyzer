import sys

from PySide6.QtWidgets import QApplication

from app.gui.main_window import MainWindow
from app.gui.styles import STYLE


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("PacketAnalyzer")
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
