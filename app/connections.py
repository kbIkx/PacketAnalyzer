from dataclasses import dataclass

from app.parser import PacketInfo


@dataclass
class Connection:
    source: str
    source_port: int
    destination: str
    destination_port: int

    packets: int = 0
    bytes: int = 0

    state: str = "UNKNOWN"
    flags: str = ""
    first_seen: float = 0
    last_seen: float = 0


class ConnectionTracker:
    def __init__(self):
        self.connections = {}

    def _key(self, packet):
        first = (packet.source, packet.source_port)
        second = (packet.destination, packet.destination_port)

        return tuple(sorted([first, second]))

    def update(self, packet: PacketInfo):
        if packet.protocol != "TCP":
            return

        if packet.source_port is None or packet.destination_port is None:
            return

        key = self._key(packet)

        if key not in self.connections:
            self.connections[key] = Connection(
                source=packet.source,
                source_port=packet.source_port,
                destination=packet.destination,
                destination_port=packet.destination_port,
                first_seen=packet.timestamp,
            )

        connection = self.connections[key]

        connection.packets += 1
        connection.bytes += packet.size
        connection.last_seen = packet.timestamp
        connection.flags = ",".join(sorted(set(filter(None, connection.flags.split(","))) | set(filter(None, packet.flags.split(",")))))

        connection.state = "Observed only"

    def all(self):
        return list(self.connections.values())
