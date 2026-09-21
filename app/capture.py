from scapy.all import conf, sniff


DEFAULT_INTERFACE_INDEX = 11


def resolve_interface(value=None):
    if value is None:
        return conf.ifaces.dev_from_index(DEFAULT_INTERFACE_INDEX)

    try:
        index = int(value)
        return conf.ifaces.dev_from_index(index)
    except (ValueError, KeyError):
        return value


class PacketCapture:
    def __init__(self, interface=None):
        self.interface = resolve_interface(interface)

    def live(self, callback):
        sniff(
            iface=self.interface,
            prn=callback,
            store=False,
        )