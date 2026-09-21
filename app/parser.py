from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from app.services import service_name


@dataclass
class PacketInfo:
    timestamp: float
    source: str
    destination: str
    protocol: str
    size: int

    source_port: int | None = None
    destination_port: int | None = None

    flags: str = ""
    seq: int | None = None
    ack: int | None = None
    window: int | None = None

    info: str = ""


def get_tcp_flags(tcp):
    names = []

    flag_map = [
        ("F", "FIN"),
        ("S", "SYN"),
        ("R", "RST"),
        ("P", "PSH"),
        ("A", "ACK"),
        ("U", "URG"),
        ("E", "ECE"),
        ("C", "CWR"),
    ]

    raw_flags = str(tcp.flags)

    for flag, name in flag_map:
        if flag in raw_flags:
            names.append(name)

    return ",".join(names)


def parse_packet(packet):
    timestamp = float(getattr(packet, "time", 0))
    size = len(packet)

    source = "?"
    destination = "?"
    protocol = "OTHER"

    source_port = None
    destination_port = None

    flags = ""
    seq = None
    ack = None
    window = None

    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst

    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst

    if packet.haslayer(TCP):
        tcp = packet[TCP]

        protocol = "TCP"

        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)

        flags = get_tcp_flags(tcp)
        seq = int(tcp.seq)
        ack = int(tcp.ack)
        window = int(tcp.window)

        info = (
            f"{source_port} ({service_name(source_port)}) -> "
            f"{destination_port} ({service_name(destination_port)}) "
            f"[{flags}] "
            f"SEQ={seq} ACK={ack} WIN={window}"
        )

    elif packet.haslayer(UDP):
        udp = packet[UDP]

        protocol = "UDP"

        source_port = int(udp.sport)
        destination_port = int(udp.dport)

        info = (
            f"{source_port} ({service_name(source_port)}) -> "
            f"{destination_port} ({service_name(destination_port)})"
        )

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        info = "ICMP packet"

    elif packet.haslayer(IPv6):
        protocol = "IPv6"
        info = "IPv6 packet"

    else:
        info = "Non-IP packet"

    return PacketInfo(
        timestamp=timestamp,
        source=source,
        destination=destination,
        protocol=protocol,
        size=size,
        source_port=source_port,
        destination_port=destination_port,
        flags=flags,
        seq=seq,
        ack=ack,
        window=window,
        info=info,
    )