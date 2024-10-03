import logging
from typing import List

import scapy.all as scapy

from marissa.pcap import Packet

logging.getLogger("scapy").setLevel(logging.CRITICAL)


class Pcap:
    @staticmethod
    def load(filename: str) -> List[Packet]:
        content = []
        with open(filename, "rb") as f:
            pcap = scapy.rdpcap(f)
            for packet in pcap:
                content.append(Packet(packet))

        return content

    @staticmethod
    def write(packets: list[str], filename: str) -> None:
        packets = [bytes.fromhex(packet) for packet in packets]
        scapy.wrpcap(filename, packets)
