from dataclasses import dataclass

from app.parser import PacketInfo


@dataclass
class PacketFilter:
    protocol: str | None = None
    port: int | None = None
    host: str | None = None
    source: str | None = None
    destination: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    text: str | None = None

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

        if self.source and packet.source != self.source:
            return False
        if self.destination and packet.destination != self.destination:
            return False
        if self.source_port is not None and packet.source_port != self.source_port:
            return False
        if self.destination_port is not None and packet.destination_port != self.destination_port:
            return False
        if self.text:
            searchable = " ".join(str(value) for value in (
                packet.source, packet.destination, packet.protocol,
                packet.source_port, packet.destination_port, packet.info,
            ))
            if self.text.casefold() not in searchable.casefold():
                return False

        return True
