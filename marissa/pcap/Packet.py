import binascii
from typing import List

from scapy.all import Packet as ScapyPacket


class Packet:
    """Packet class to represent a packet in a pcap file."""

    def __init__(self, packet: ScapyPacket) -> None:
        self.packet = packet
        self.hex = binascii.hexlify(bytes(packet)).decode("utf-8")
        self.length = len(self.hex)
        self.timestamp = float(packet.time)

    def __str__(self):
        return self.hex

    def get_applayer(self) -> str:
        """Get the application layer of the packet.

        Returns:
            str: Hexadecimal representation of the application layer
        """
        layers = self._get_packet_layers()

        if layers[2].name == "TCP" or layers[2].name == "UDP":
            return binascii.hexlify(bytes(layers[3])).decode("utf-8")
        else:
            return binascii.hexlify(bytes(layers[2])).decode("utf-8")

    def _get_packet_layers(self) -> List[ScapyPacket]:
        """Get the layers of the packet.

        Returns:
            List[ScapyPacket]: List of layers
        """
        counter = 0
        layers = []
        while True:
            layer = self.packet.getlayer(counter)
            if layer is None:
                break

            layers.append(layer)
            counter += 1

        return layers
