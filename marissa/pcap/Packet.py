import binascii
from typing import List

from scapy.all import Packet as ScapyPacket


class Packet:
    """Packet class to represent a packet in a pcap file."""

    def __init__(self, packet: ScapyPacket) -> None:
        self.packet = packet

    @property
    def hex(self):
        return binascii.hexlify(bytes(self.packet)).decode("utf-8")

    @property
    def length(self):
        return len(self.hex)

    @property
    def timestamp(self):
        return self.packet.time

    def __str__(self):
        return self.hex

    def get_applayer(self) -> str:
        """Get the application layer of the packet.

        Returns:
            str: Hexadecimal representation of the application layer
        """
        layers = self._get_packet_layers()

        app_layer = 2

        if layers[1].name == "802.1Q":
            app_layer += 1

        if app_layer >= len(layers):
            app_layer = len(layers) - 1

        if layers[app_layer].name == "TCP" or layers[app_layer].name == "UDP":
            app_layer += 1

        return binascii.hexlify(bytes(layers[app_layer])).decode("utf-8")

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

    def get_layer(self, layer: int) -> str:
        """Get the layer of the packet.

        Args:
            layer (int): Layer to get

        Returns:
            str: Hexadecimal representation of the layer
        """
        layers = self._get_packet_layers()

        if layer >= len(layers):
            return ""

        return binascii.hexlify(bytes(layers[layer])).decode("utf-8")
