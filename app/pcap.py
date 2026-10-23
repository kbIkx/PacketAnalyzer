from pathlib import Path

from scapy.all import PcapReader, wrpcap


def save_packets(packets, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if packets:
        wrpcap(str(path), packets)


def read_packets(path):
    with PcapReader(str(path)) as reader:
        return list(reader)


def iter_packets(path):
    with PcapReader(str(path)) as reader:
        yield from reader
