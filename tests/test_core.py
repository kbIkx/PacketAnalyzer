from pathlib import Path
from threading import Event

import pytest
from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Ether
from scapy.layers.inet6 import ICMPv6EchoRequest

from app.capture import PacketCapture
from app.connections import ConnectionTracker
from app.filters import PacketFilter
from app.parser import parse_packet
from app.pcap import iter_packets, read_packets, save_packets
from app.statistics import TrafficStatistics


@pytest.mark.parametrize("packet,protocol", [
    (Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=443, flags="S"), "TCP"),
    (Ether()/IP()/UDP(sport=53, dport=50000), "UDP"),
    (Ether()/IP()/ICMP(), "ICMP"),
    (Ether()/ARP(psrc="10.0.0.1", pdst="10.0.0.2"), "ARP"),
    (Ether()/IPv6(src="2001:db8::1", dst="2001:db8::2")/ICMPv6EchoRequest(), "ICMPv6"),
    (Ether()/IPv6()/TCP(sport=5, dport=6), "TCP"),
    (Ether(), "OTHER"),
])
def test_parser_protocols(packet, protocol):
    info = parse_packet(packet)
    assert info.protocol == protocol
    assert info.size == len(packet)


def test_filter_by_each_endpoint_and_text():
    info = parse_packet(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=443))
    assert PacketFilter(source="10.0.0.1", destination="10.0.0.2",
                        source_port=1234, destination_port=443, text="443").matches(info)
    assert PacketFilter(host="10.0.0.2", port=1234).matches(info)
    assert not PacketFilter(source="10.0.0.2").matches(info)
    assert not PacketFilter(destination_port=80).matches(info)


def test_statistics_and_bidirectional_flow():
    first = parse_packet(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5, dport=6, flags="S"))
    second = parse_packet(Ether()/IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=6, dport=5, flags="A"))
    stats = TrafficStatistics()
    tracker = ConnectionTracker()
    for info in (first, second):
        stats.update(info)
        tracker.update(info)
    assert stats.total_packets == 2
    assert stats.total_bytes == first.size + second.size
    assert stats.host_bytes["10.0.0.1"] == stats.total_bytes
    flow = tracker.all()[0]
    assert flow.packets == 2
    assert flow.bytes == stats.total_bytes
    assert "SYN" in flow.flags and "ACK" in flow.flags
    assert flow.state == "Observed only"


def test_pcap_roundtrip_and_bad_file(tmp_path):
    path = tmp_path / "synthetic.pcap"
    packet = Ether()/IP()/UDP(sport=1234, dport=53)
    save_packets([packet], path)
    assert len(read_packets(path)) == 1
    assert len(list(iter_packets(path))) == 1
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap")
    with pytest.raises(Exception):
        read_packets(bad)


def test_capture_worker_starts_stops_and_rejects_duplicate(monkeypatch):
    entered = Event()

    def fake_sniff(**kwargs):
        entered.set()

    monkeypatch.setattr("app.capture.sniff", fake_sniff)
    capture = PacketCapture("fake")
    capture.start(lambda packet: None)
    assert entered.wait(2)
    with pytest.raises(RuntimeError):
        capture.start(lambda packet: None)
    capture.stop()
    assert not capture.running
