import logging
from typing import List

import scapy.all as scapy

from marissa.pcap import Packet

logging.getLogger("scapy").setLevel(logging.CRITICAL)


class Pcap:
    def __init__(
        self,
        filename,
    ):
        self.filename = filename

    def load(self) -> List[Packet]:
        content = []
        with open(self.filename, "rb") as f:
            pcap = scapy.rdpcap(f)
            for packet in pcap:
                content.append(Packet(packet))

        return content

    def write(self, packets: list[str], filename: str) -> None:
        packets = [bytes.fromhex(packet) for packet in packets]
        scapy.wrpcap(filename, packets)
