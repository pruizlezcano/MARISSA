import binascii


class Packet:
    def __init__(self, packet) -> None:
        self.hex = binascii.hexlify(bytes(packet)).decode("utf-8")
        self.length = len(self.hex)
        self.binary = binascii.unhexlify(self.hex)
        self.ascii = binascii.unhexlify(self.hex).decode("utf-8", errors="ignore")
        self.timestamp = float(packet.time)

    def __str__(self):
        return self.hex
