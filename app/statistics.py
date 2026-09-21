from collections import Counter


class TrafficStatistics:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0

        self.protocols = Counter()
        self.ports = Counter()
        self.hosts = Counter()
        self.connections = Counter()

    def update(self, packet):
        self.total_packets += 1
        self.total_bytes += packet.size

        self.protocols[packet.protocol] += 1

        self.hosts[packet.source] += 1
        self.hosts[packet.destination] += 1

        if packet.source_port is not None:
            self.ports[packet.source_port] += 1

        if packet.destination_port is not None:
            self.ports[packet.destination_port] += 1

        connection = (
            f"{packet.source}:{packet.source_port}"
            f" -> "
            f"{packet.destination}:{packet.destination_port}"
        )

        self.connections[connection] += 1

    def top_ports(self, limit=10):
        return self.ports.most_common(limit)

    def top_hosts(self, limit=10):
        return self.hosts.most_common(limit)

    def top_connections(self, limit=10):
        return self.connections.most_common(limit)

    def print_summary(self):
        print()
        print("=" * 70)
        print("TRAFFIC STATISTICS")
        print("=" * 70)

        print(f"Packets: {self.total_packets}")
        print(f"Bytes:   {self.total_bytes:,}")

        print()
        print("Protocols:")

        for protocol, count in self.protocols.most_common():
            print(f"  {protocol:<10} {count}")

        print()
        print("Top ports:")

        for port, count in self.top_ports():
            print(f"  {port:<10} {count}")

        print()
        print("Top hosts:")

        for host, count in self.top_hosts():
            print(f"  {host:<25} {count}")

        print()
        print("Top connections:")

        for connection, count in self.top_connections():
            print(f"  {connection:<50} {count}")

        print("=" * 70)


def print_connections(tracker):
    print()
    print("=" * 100)
    print("TCP CONNECTIONS")
    print("=" * 100)

    connections = tracker.all()

    if not connections:
        print("No TCP connections.")
        print("=" * 100)
        return

    connections.sort(
        key=lambda connection: connection.bytes,
        reverse=True,
    )

    for connection in connections:
        print(
            f"{connection.source}:{connection.source_port}"
            f" -> "
            f"{connection.destination}:{connection.destination_port}"
            f" | {connection.state:<12}"
            f" | packets={connection.packets:<6}"
            f" | bytes={connection.bytes:<10}"
            f" | {connection.flags}"
        )

    print("=" * 100)