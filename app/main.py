import argparse
import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent),
)

from app.capture import PacketCapture
from app.connections import ConnectionTracker
from app.filters import PacketFilter
from app.parser import parse_packet
from app.pcap import read_packets, save_packets
from app.statistics import TrafficStatistics, print_connections


def build_parser():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer"
    )

    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "icmp", "ipv6"],
        help="Filter by protocol",
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Filter by source or destination port",
    )

    parser.add_argument(
        "--host",
        help="Filter by source or destination host",
    )

    parser.add_argument(
        "--interface",
        help="Interface index or interface name",
    )

    parser.add_argument(
        "--save",
        help="Save captured packets to PCAP",
    )

    parser.add_argument(
        "--read",
        help="Read packets from PCAP",
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show traffic statistics",
    )

    parser.add_argument(
        "--connections",
        action="store_true",
        help="Show TCP connections",
    )

    return parser


def print_packet(packet_info):
    print(
        f"{packet_info.protocol:<6} "
        f"{packet_info.source:<22} -> "
        f"{packet_info.destination:<22} "
        f"{packet_info.size:>6} B | "
        f"{packet_info.info}"
    )


def main():
    parser = build_parser()
    args = parser.parse_args()

    packet_filter = PacketFilter(
        protocol=args.protocol,
        port=args.port,
        host=args.host,
    )

    stats = TrafficStatistics()
    tracker = ConnectionTracker()

    saved_packets = []

    def process(packet, save=True):
        if save:
            saved_packets.append(packet)

        info = parse_packet(packet)

        if not packet_filter.matches(info):
            return

        stats.update(info)
        tracker.update(info)

        print_packet(info)

    # ---------------------------------------------------------
    # PCAP MODE
    # ---------------------------------------------------------

    if args.read:
        print("=" * 70)
        print("PCAP PLAYBACK")
        print("=" * 70)
        print(f"File: {args.read}")
        print()

        packets = read_packets(args.read)

        print(f"Packets loaded: {len(packets)}")
        print()

        for packet in packets:
            process(packet, save=False)

        if args.stats:
            stats.print_summary()

        if args.connections:
            print_connections(tracker)

        return

    # ---------------------------------------------------------
    # LIVE MODE
    # ---------------------------------------------------------

    capture = PacketCapture(args.interface)

    print("=" * 70)
    print("NETWORK PACKET ANALYZER")
    print("=" * 70)
    print(f"Interface: {capture.interface}")
    print("Capture started.")
    print("Press Ctrl+C to stop.")
    print()

    try:
        capture.live(process)

    except KeyboardInterrupt:
        print()
        print("Capture stopped.")

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    if args.save:
        save_packets(
            saved_packets,
            args.save,
        )

        print(
            f"Saved {len(saved_packets)} "
            f"packets to {args.save}"
        )

    # ---------------------------------------------------------
    # REPORTS
    # ---------------------------------------------------------

    if args.stats:
        stats.print_summary()

    if args.connections:
        print_connections(tracker)


if __name__ == "__main__":
    main()