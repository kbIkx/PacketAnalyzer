from dataclasses import dataclass

from app.parser import PacketInfo


@dataclass
class PacketFilter:
    protocol: str | None = None
    port: int | None = None
    host: str | None = None

    def matches(self, packet: PacketInfo):
        if self.protocol:
            if packet.protocol.lower() != self.protocol.lower():
                return False

        if self.port is not None:
            if (
                packet.source_port != self.port
                and packet.destination_port != self.port
            ):
                return False

        if self.host:
            if (
                packet.source != self.host
                and packet.destination != self.host
            ):
                return False

        return True