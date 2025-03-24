import logging
from typing import List

import scapy.all as scapy

from marissa.pcap import Packet

logging.getLogger("scapy").setLevel(logging.CRITICAL)


class Pcap:
    """Pcap class to handle pcap files."""

    @staticmethod
    def load(filename: str) -> List[Packet]:
        """Load a pcap file.

        Args:
            filename (str): Path to the pcap file.

        Returns:
            List[Packet]: List of packets in the pcap file.
        """
        with open(filename, "rb") as f:
            pcap = scapy.rdpcap(f)

        return [Packet(packet) for packet in pcap]

    @staticmethod
    def write(packets: List[str], filename: str) -> None:
        """Write packets to a pcap file.

        Args:
            packets (List[str]): List of the hexadecimal representation of the packets
            filename (str): Path to the pcap file
        """
        packets = [bytes.fromhex(packet) for packet in packets]
        scapy.wrpcap(filename, packets)
