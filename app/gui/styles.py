"""Shared color and type tokens for the desktop interface."""

from string import Template


COLORS = {
    "background": "#0D1117", "sidebar": "#151B23", "surface": "#171E28",
    "elevated": "#1C2430", "border": "#293241", "text": "#E6EDF5",
    "muted": "#95A7BB", "quiet": "#6F8299", "primary": "#50B8E7",
    "primary_hover": "#70CAF0", "primary_faint": "#193B51",
    "success": "#60D39C", "warning": "#E5B662", "error": "#EE858E",
}


STYLE = Template("""
QWidget { color: $text; font-family: 'Segoe UI'; font-size: 10pt; }
QWidget#appRoot { background: $background; }
QFrame#sidebar { background: $sidebar; border-right: 1px solid $border; }
QLabel#brandTitle { color: $text; font-size: 15pt; font-weight: 700; }
QLabel#brandCaption, QLabel#eyebrow, QLabel#fieldLabel {
    color: $quiet; font-size: 8pt; font-weight: 700; letter-spacing: 1px;
}
QLabel#brandCaption { color: $primary; }
QLabel#muted { color: $muted; font-size: 9pt; }
QLabel#pageTitle { color: $text; font-size: 18pt; font-weight: 700; }
QLabel#pageSubtitle { color: $muted; font-size: 9pt; }
QLabel#status { color: $muted; font-size: 9pt; }
QLabel#status[tone="active"], QLabel#status[tone="success"] { color: $success; }
QLabel#status[tone="error"] { color: $error; }
QLabel#status[tone="busy"] { color: $warning; }
QFrame#statusDot { background: $quiet; border-radius: 4px; }
QFrame#statusDot[tone="active"], QFrame#statusDot[tone="success"] { background: $success; }
QFrame#statusDot[tone="error"] { background: $error; }
QFrame#statusDot[tone="busy"] { background: $warning; }
QFrame#topBar, QFrame#sectionHeading { border-bottom: 1px solid $border; }
QFrame#panel, QFrame#metricCard { background: $surface; border: 1px solid $border; border-radius: 7px; }
QFrame#metricCard { background: $elevated; }
QLabel#metricLabel { color: $muted; font-size: 8pt; font-weight: 700; }
QLabel#metricValue { color: $text; font-size: 17pt; font-weight: 700; }
QWidget#filterCell { background: transparent; }
QToolButton#nav {
    color: $muted; background: transparent; border: 0; border-left: 3px solid transparent;
    text-align: left; padding: 10px 12px; min-height: 27px; font-weight: 600;
}
QToolButton#nav:hover { color: $text; background: $elevated; }
QToolButton#nav:checked { color: $primary; background: $primary_faint; border-left-color: $primary; }
QPushButton, QComboBox, QLineEdit, QSpinBox {
    background: $elevated; color: $text; border: 1px solid $border;
    border-radius: 5px; padding: 4px 9px; min-height: 26px;
}
QPushButton { font-weight: 600; padding-left: 12px; padding-right: 12px; }
QPushButton:hover, QComboBox:hover { background: #263443; border-color: #4A6177; }
QPushButton:pressed { background: #304257; }
QPushButton:disabled { color: $quiet; background: $surface; border-color: $border; }
QPushButton#primary, QPushButton#apply { color: #08131B; background: $primary; border-color: $primary; }
QPushButton#primary:hover, QPushButton#apply:hover { background: $primary_hover; border-color: $primary_hover; }
QPushButton#primary:disabled { color: $quiet; background: $primary_faint; border-color: $border; }
QPushButton#danger { color: $error; background: #35262E; border-color: #69434D; }
QPushButton#danger:hover { background: #4A303A; }
QPushButton#danger:disabled { color: $quiet; background: $surface; border-color: $border; }
QPushButton#quiet { background: transparent; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border-color: $primary; }
QLineEdit::placeholder { color: $quiet; }
QComboBox QAbstractItemView { background: $elevated; color: $text; border: 1px solid $border; selection-background-color: $primary_faint; }
QCheckBox { color: $muted; spacing: 7px; }
QCheckBox::indicator { width: 15px; height: 15px; border: 1px solid #60758B; border-radius: 3px; background: $sidebar; }
QCheckBox::indicator:checked { background: $primary; border-color: $primary; }
QSpinBox::up-button, QSpinBox::down-button { border: 0; background: transparent; width: 16px; }
QTableView, QTableWidget, QTreeWidget {
    background: $background; alternate-background-color: #111823; color: $text;
    border: 0; selection-background-color: $primary_faint; selection-color: #FFFFFF;
    gridline-color: $border;
}
QHeaderView::section {
    background: $sidebar; color: $muted; padding: 6px 9px; border: 0;
    border-bottom: 1px solid $border; font-size: 9pt; font-weight: 700;
}
QTableView::item:selected, QTableWidget::item:selected, QTreeWidget::item:selected { background: $primary_faint; color: #FFFFFF; }
QTableView::item:hover, QTableWidget::item:hover { background: #1A2A3A; }
QPlainTextEdit { background: $background; color: #BBD0E4; border: 0; padding: 9px; font-family: Consolas; font-size: 9pt; }
QSplitter::handle { background: $border; width: 3px; height: 3px; }
QScrollBar:vertical { background: $background; width: 9px; margin: 0; }
QScrollBar::handle:vertical { background: #405165; border-radius: 4px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QToolTip { color: $text; background: $elevated; border: 1px solid #4A6177; padding: 5px; }
""").substitute(COLORS)
