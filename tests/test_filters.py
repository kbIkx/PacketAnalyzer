from types import SimpleNamespace

from app.filters import PacketFilter


def make_packet(
    protocol="TCP",
    source="192.168.0.10",
    destination="8.8.8.8",
    source_port=50000,
    destination_port=443,
):
    return SimpleNamespace(
        protocol=protocol,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
    )


def test_protocol_filter():
    packet = make_packet(protocol="TCP")

    assert PacketFilter(protocol="tcp").matches(packet)
    assert not PacketFilter(protocol="udp").matches(packet)


def test_port_filter():
    packet = make_packet(destination_port=443)

    assert PacketFilter(port=443).matches(packet)
    assert not PacketFilter(port=80).matches(packet)


def test_host_filter():
    packet = make_packet(
        source="192.168.0.21",
        destination="8.8.8.8",
    )

    assert PacketFilter(host="192.168.0.21").matches(packet)
    assert PacketFilter(host="8.8.8.8").matches(packet)
    assert not PacketFilter(host="1.1.1.1").matches(packet)


def test_combined_filter():
    packet = make_packet(
        protocol="TCP",
        destination="8.8.8.8",
        destination_port=443,
    )

    packet_filter = PacketFilter(
        protocol="tcp",
        port=443,
        host="8.8.8.8",
    )

    assert packet_filter.matches(packet)