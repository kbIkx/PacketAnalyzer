"""Widget composition for the PacketAnalyzer desktop window."""

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QFrame,
    QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QSizePolicy, QSpinBox, QSplitter, QStackedWidget, QTableView, QTableWidget,
    QToolButton, QVBoxLayout, QWidget)

from app.gui.icons import icon
from app.gui.packet_details import PacketDetails
from app.gui.statistics_view import StatisticsView


PAGES = (
    ("Capture", "Live and offline packet inspection", "capture"),
    ("Statistics", "Traffic rates, protocols and top endpoints", "statistics"),
    ("Connections", "Observed TCP flows", "connections"),
    ("PCAP Files", "Open and export captured traffic", "files"),
    ("Settings", "Display and memory preferences", "settings"),
)


def _label(text, name="muted"):
    label = QLabel(text)
    label.setObjectName(name)
    return label


def _button(text, callback, name="quiet", tip=""):
    button = QPushButton(text)
    button.setObjectName(name)
    button.clicked.connect(callback)
    if tip:
        button.setToolTip(tip)
    return button


def build_window(w):
    root = QWidget()
    root.setObjectName("appRoot")
    w.setCentralWidget(root)
    shell = QHBoxLayout(root)
    shell.setContentsMargins(0, 0, 0, 0)
    shell.setSpacing(0)

    sidebar = QFrame()
    sidebar.setObjectName("sidebar")
    sidebar.setFixedWidth(188)
    w.sidebar = sidebar
    shell.addWidget(sidebar)
    side = QVBoxLayout(sidebar)
    side.setContentsMargins(0, 20, 0, 16)
    side.setSpacing(0)
    brand = _label("PacketAnalyzer", "brandTitle")
    w.brand_label = brand
    brand.setContentsMargins(20, 0, 0, 0)
    side.addWidget(brand)
    caption = _label("NETWORK WORKSPACE", "brandCaption")
    w.brand_caption = caption
    caption.setContentsMargins(20, 1, 0, 0)
    side.addWidget(caption)
    side.addSpacing(33)
    nav_group = QButtonGroup(w)
    nav_group.setExclusive(True)
    w.nav_buttons = []
    for index, (title, _, icon_name) in enumerate(PAGES):
        button = QToolButton()
        button.setObjectName("nav")
        button.setText(title)
        button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        button.setIcon(icon(icon_name))
        button.setIconSize(QSize(18, 18))
        button.setCheckable(True)
        button.setFixedWidth(188)
        button.setToolTip(title)
        button.clicked.connect(lambda checked=False, page=index: w._set_page(page))
        nav_group.addButton(button)
        side.addWidget(button)
        w.nav_buttons.append(button)
    side.addStretch()
    footer = _label("PACKETANALYZER  /  v1.0", "brandCaption")
    w.sidebar_footer = footer
    footer.setContentsMargins(20, 0, 0, 0)
    side.addWidget(footer)
    side.addSpacing(8)

    main = QWidget()
    shell.addWidget(main, 1)
    column = QVBoxLayout(main)
    column.setContentsMargins(0, 0, 0, 0)
    column.setSpacing(0)

    header = QFrame()
    header.setObjectName("topBar")
    column.addWidget(header)
    top = QVBoxLayout(header)
    top.setContentsMargins(22, 13, 22, 13)
    top.setSpacing(11)
    title_row = QHBoxLayout()
    title_row.setSpacing(9)
    top.addLayout(title_row)
    titles = QVBoxLayout()
    titles.setSpacing(0)
    w.page_title = _label("Capture", "pageTitle")
    w.page_subtitle = _label("Live and offline packet inspection", "pageSubtitle")
    titles.addWidget(w.page_title)
    titles.addWidget(w.page_subtitle)
    title_row.addLayout(titles)
    title_row.addStretch()
    w.status_dot = QFrame()
    w.status_dot.setObjectName("statusDot")
    w.status_dot.setFixedSize(9, 9)
    title_row.addWidget(w.status_dot)
    w.status = _label("Idle", "status")
    w.status.setMaximumWidth(380)
    title_row.addWidget(w.status)
    w._set_status("Idle")

    controls = QHBoxLayout()
    controls.setSpacing(8)
    top.addLayout(controls)
    controls.addWidget(_label("INTERFACE", "eyebrow"))
    w.interfaces = QComboBox()
    w.interfaces.setMinimumWidth(210)
    w.interfaces.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    w.interfaces.setToolTip("Select an interface for live capture")
    controls.addWidget(w.interfaces, 1)
    controls.addWidget(_button("Refresh", w.refresh_interfaces, tip="Refresh available network adapters (Ctrl+R)"))
    w.start_button = _button("Start Capture", w.start_capture, "primary", "Start live capture (F5)")
    w.stop_button = _button("Stop", w.stop_capture, "danger", "Stop live capture")
    w.stop_button.setEnabled(False)
    controls.addWidget(w.start_button)
    controls.addWidget(w.stop_button)
    controls.addSpacing(10)
    w.header_count = _label("0 packets", "muted")
    controls.addWidget(w.header_count)

    w.workspace_tabs = QStackedWidget()
    column.addWidget(w.workspace_tabs, 1)
    _capture_page(w)
    w.statistics_view = StatisticsView()
    w.workspace_tabs.addWidget(w.statistics_view)
    _connections_page(w)
    _files_page(w)
    _settings_page(w)
    w._set_page(0)
    _shortcuts(w)


def _capture_page(w):
    page = QWidget()
    w.workspace_tabs.addWidget(page)
    layout = QVBoxLayout(page)
    layout.setContentsMargins(16, 11, 16, 12)
    layout.setSpacing(9)

    filter_bar = QFrame()
    filter_bar.setObjectName("panel")
    layout.addWidget(filter_bar)
    filter_layout = QVBoxLayout(filter_bar)
    filter_layout.setContentsMargins(12, 9, 12, 9)
    filter_layout.setSpacing(8)
    quick = QHBoxLayout()
    quick.setSpacing(8)
    filter_layout.addLayout(quick)
    quick.addWidget(_label("DISPLAY FILTER", "eyebrow"))
    w.protocol = QComboBox()
    w.protocol.addItems(("All protocols", "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IPv6", "OTHER"))
    w.protocol.setFixedWidth(135)
    quick.addWidget(w.protocol)
    w.inputs = {}
    search = QLineEdit()
    search.setPlaceholderText("Search packet metadata…")
    search.setClearButtonEnabled(True)
    search.returnPressed.connect(w.apply_filters)
    search.setToolTip("Search addresses, protocol and summary text (Ctrl+F)")
    w.inputs["text"] = search
    quick.addWidget(search, 1)
    w.filter_toggle = _button("More filters", lambda: None)
    w.filter_toggle.setCheckable(True)
    w.filter_toggle.toggled.connect(w._toggle_filters)
    quick.addWidget(w.filter_toggle)
    quick.addWidget(_button("Reset", w.reset_filters))
    quick.addWidget(_button("Apply", w.apply_filters, "apply"))

    w.filter_body = QWidget()
    filter_layout.addWidget(w.filter_body)
    grid = QGridLayout(w.filter_body)
    grid.setContentsMargins(0, 0, 0, 0)
    grid.setHorizontalSpacing(9)
    grid.setVerticalSpacing(7)
    specs = (("Source IP", "source"), ("Destination IP", "destination"),
             ("Either IP", "host"), ("Source port", "source_port"),
             ("Destination port", "destination_port"), ("Either port", "port"))
    for index, (title, key) in enumerate(specs):
        cell = QWidget()
        cell.setObjectName("filterCell")
        cell_layout = QVBoxLayout(cell)
        cell_layout.setContentsMargins(0, 0, 0, 0)
        cell_layout.setSpacing(3)
        cell_layout.addWidget(_label(title.upper(), "fieldLabel"))
        field = QLineEdit()
        field.setPlaceholderText("Any")
        field.returnPressed.connect(w.apply_filters)
        cell_layout.addWidget(field)
        w.inputs[key] = field
        grid.addWidget(cell, index // 3, index % 3)
    for column in range(3):
        grid.setColumnStretch(column, 1)
    w.filter_toggle.setChecked(str(w.settings.value("filters_open", "false")).lower() == "true")
    w._toggle_filters(w.filter_toggle.isChecked())

    workspace = QFrame()
    workspace.setObjectName("panel")
    layout.addWidget(workspace, 1)
    inner = QVBoxLayout(workspace)
    inner.setContentsMargins(0, 0, 0, 0)
    inner.setSpacing(0)
    packet_heading = QFrame()
    packet_heading.setObjectName("sectionHeading")
    heading = QHBoxLayout(packet_heading)
    heading.setContentsMargins(13, 5, 13, 5)
    heading.setSpacing(9)
    heading.addWidget(_label("PACKETS", "eyebrow"))
    heading.addStretch()
    w.pause = QCheckBox("Pause display")
    w.pause.setToolTip("Keep capturing but pause updates to the table")
    w.pause.toggled.connect(w._toggle_pause)
    heading.addWidget(w.pause)
    w.count_label = _label("0 shown / 0 retained / 0 observed")
    heading.addWidget(w.count_label)
    heading.addWidget(_button("Clear", w.clear, tip="Clear retained packets and statistics"))
    inner.addWidget(packet_heading)
    w.packet_splitter = QSplitter(Qt.Orientation.Vertical)
    w.packet_splitter.setChildrenCollapsible(False)
    inner.addWidget(w.packet_splitter, 1)
    table_area = QWidget()
    table_layout = QVBoxLayout(table_area)
    table_layout.setContentsMargins(0, 0, 0, 0)
    table_layout.setSpacing(0)
    w.empty_label = _label("No packets yet  ·  Start a capture or open a PCAP file", "muted")
    w.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    w.empty_label.setMinimumHeight(42)
    table_layout.addWidget(w.empty_label)
    w.table = QTableView()
    w.table.setModel(w.proxy)
    w.table.setSortingEnabled(True)
    w.table.setShowGrid(False)
    w.table.setAlternatingRowColors(True)
    w.table.verticalHeader().setDefaultSectionSize(31)
    w.table.horizontalHeader().setMinimumHeight(34)
    w.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
    w.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
    w.table.verticalHeader().hide()
    w.table.horizontalHeader().setStretchLastSection(True)
    for col, width in enumerate((62, 116, 155, 155, 91, 76)):
        w.table.setColumnWidth(col, width)
    w.table.selectionModel().currentRowChanged.connect(w._show_packet)
    w.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    w.table.customContextMenuRequested.connect(w._packet_menu)
    table_layout.addWidget(w.table, 1)
    w.packet_splitter.addWidget(table_area)
    w.details = PacketDetails()
    w.packet_splitter.addWidget(w.details)
    w.packet_splitter.setSizes((550, 450))
    state = w.settings.value("packet_splitter_v2")
    if state:
        w.packet_splitter.restoreState(state)
    state = w.settings.value("details_splitter_v2")
    if state:
        w.details.splitter.restoreState(state)


def _connections_page(w):
    page = QWidget()
    w.workspace_tabs.addWidget(page)
    layout = QVBoxLayout(page)
    layout.setContentsMargins(16, 13, 16, 15)
    layout.addWidget(_label("Flows are inferred from observed packets. A capture may begin mid-connection.", "muted"))
    w.connections = QTableWidget(0, 9)
    w.connections.setHorizontalHeaderLabels(("Source", "Src port", "Destination", "Dst port",
        "Protocol", "Packets", "Bytes", "First / Last", "Observed flags"))
    w.connections.horizontalHeader().setStretchLastSection(True)
    w.connections.verticalHeader().hide()
    w.connections.setAlternatingRowColors(True)
    w.connections.setShowGrid(False)
    w.connections.verticalHeader().setDefaultSectionSize(31)
    layout.addWidget(w.connections, 1)


def _files_page(w):
    page = QWidget()
    w.workspace_tabs.addWidget(page)
    layout = QVBoxLayout(page)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(13)
    layout.addWidget(_label("PCAP WORKSPACE", "eyebrow"))
    layout.addWidget(_label("Open a capture for offline analysis or export the traffic currently in memory."))
    actions = QHBoxLayout()
    actions.setSpacing(9)
    actions.addWidget(_button("Open PCAP…", w.open_pcap, "primary", "Load a .pcap file (Ctrl+O)"))
    actions.addWidget(_button("Save retained PCAP…", w.save_pcap, tip="Save all retained packets, regardless of display filter (Ctrl+S)"))
    actions.addWidget(_button("Export displayed CSV…", w.export_csv, tip="Export filtered packet metadata only (Ctrl+E)"))
    actions.addStretch()
    layout.addLayout(actions)
    scope = QFrame()
    scope.setObjectName("panel")
    box = QVBoxLayout(scope)
    box.setContentsMargins(15, 13, 15, 13)
    box.setSpacing(6)
    box.addWidget(_label("EXPORT SCOPE", "eyebrow"))
    box.addWidget(_label("PCAP includes all packets retained in memory. Display filters do not change this export."))
    box.addWidget(_label("CSV includes displayed rows and metadata only. Packet payloads are omitted."))
    layout.addWidget(scope)
    layout.addStretch()


def _settings_page(w):
    page = QWidget()
    w.workspace_tabs.addWidget(page)
    layout = QVBoxLayout(page)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(13)
    layout.addWidget(_label("DISPLAY & MEMORY", "eyebrow"))
    panel = QFrame()
    panel.setObjectName("panel")
    grid = QGridLayout(panel)
    grid.setContentsMargins(15, 14, 15, 14)
    grid.setHorizontalSpacing(30)
    grid.setVerticalSpacing(12)
    grid.addWidget(_label("Retained packet limit"), 0, 0)
    w.limit = QSpinBox()
    w.limit.setRange(100, 100000)
    w.limit.setSingleStep(1000)
    w.limit.setValue(w.maximum)
    w.limit.valueChanged.connect(w._set_limit)
    grid.addWidget(w.limit, 0, 1)
    grid.addWidget(_label("Oldest packets are removed when the limit is reached."), 0, 2)
    grid.addWidget(_label("Auto scroll"), 1, 0)
    w.scroll = QCheckBox("Follow newest packets")
    w.scroll.setChecked(str(w.settings.value("auto_scroll", "true")).lower() == "true")
    grid.addWidget(w.scroll, 1, 1, 1, 2)
    grid.addWidget(_label("Chart refresh interval"), 2, 0)
    w.chart_interval = QSpinBox()
    w.chart_interval.setRange(1, 10)
    w.chart_interval.setSuffix(" s")
    w.chart_interval.setValue(max(1, min(10, int(w.settings.value("chart_interval", 1)))))
    w.chart_interval.valueChanged.connect(lambda value: w.chart_timer.setInterval(value * 1000)
                                           if hasattr(w, "chart_timer") else None)
    grid.addWidget(w.chart_interval, 2, 1)
    grid.addWidget(_label("Statistics and charts update at this interval."), 2, 2)
    grid.setColumnStretch(2, 1)
    layout.addWidget(panel)
    layout.addStretch()


def _shortcuts(w):
    for label, shortcut, callback in (
        ("Open PCAP", "Ctrl+O", w.open_pcap),
        ("Save PCAP", "Ctrl+S", w.save_pcap),
        ("Export CSV", "Ctrl+E", w.export_csv),
        ("Focus search", "Ctrl+F", lambda: (w._set_page(0), w.inputs["text"].setFocus())),
        ("Refresh interfaces", "Ctrl+R", w.refresh_interfaces),
        ("Start or stop capture", "F5", lambda: w.stop_capture() if w.capture and w.capture.running else w.start_capture()),
    ):
        action = QAction(label, w)
        action.setShortcut(shortcut)
        action.triggered.connect(callback)
        w.addAction(action)
