import logging

import scapy.all as scapy

from marissa.pcap import Packet

logging.getLogger("scapy").setLevel(logging.CRITICAL)


class Pcap:
    def __init__(
        self,
        filename,
    ):
        self.filename = filename
        self.content = []

    def load(self) -> list[Packet]:
        with open(self.filename, "rb") as f:
            pcap = scapy.rdpcap(f)
            for packet in pcap:
                self.content.append(Packet(packet))

        return self.content

    def write(self, packets: list[str], filename: str):
        packets = [bytes.fromhex(packet) for packet in packets]
        scapy.wrpcap(filename, packets)
