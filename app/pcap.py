from pathlib import Path

from scapy.all import rdpcap, wrpcap


def save_packets(packets, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if packets:
        wrpcap(str(path), packets)


def read_packets(path):
    return rdpcap(str(path))