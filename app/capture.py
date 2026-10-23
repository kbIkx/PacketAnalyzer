from threading import Event, Thread

from scapy.all import conf, sniff


def resolve_interface(value=None):
    if value is None:
        return conf.iface

    try:
        index = int(value)
        return conf.ifaces.dev_from_index(index)
    except (ValueError, KeyError):
        return value


class PacketCapture:
    def __init__(self, interface=None):
        self.interface = resolve_interface(interface)
        self._stop = Event()
        self._thread = None

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def live(self, callback):
        while not self._stop.is_set():
            sniff(iface=self.interface, prn=callback, store=False, timeout=1)

    def start(self, callback, on_error=None):
        if self.running:
            raise RuntimeError("Capture is already running")
        self._stop.clear()

        def run():
            try:
                self.live(callback)
            except Exception as exc:
                if on_error:
                    on_error(exc)

        self._thread = Thread(target=run, name="packet-capture", daemon=True)
        self._thread.start()

    def stop(self, wait=True):
        self._stop.set()
        if wait and self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)


def available_interfaces():
    return [
        (f"{iface.name} ({iface.description})" if iface.description and iface.description != iface.name else iface.name, iface)
        for iface in conf.ifaces.values() if iface.name
    ]
