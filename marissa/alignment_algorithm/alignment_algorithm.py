import os
import re
from abc import ABC, abstractmethod

from marissa.Logger import Logger

conversion_table = {
    "0": "G",
    "1": "H",
    "2": "I",
    "3": "J",
    "4": "K",
    "5": "L",
    "6": "M",
    "7": "N",
    "8": "O",
    "9": "P",
}


class AlignmentAlgorithm(ABC):
    def __init__(self):
        self.logger = Logger()

    @staticmethod
    def _to_dna_sequence(item) -> str:
        item = item.upper()
        for key, value in conversion_table.items():
            item = item.replace(key, value)
        return item

    def encode(self, data, output_file: str) -> None:
        """Encode the data to a file.

        Args:
            data (list[str]): Data to encode.
            output_file (str): File to write the encoded data to.
        """
        with open(output_file, "w") as f:
            for i, item in enumerate(data):
                dna_sequence = self._to_dna_sequence(item)
                f.write(f">MSG.{i:0{len(str(len(data)))}}\n")

                f.write(f"{dna_sequence}\n")

    @staticmethod
    def _to_hex(dna: str) -> str:
        dna = dna.upper()
        for key, value in conversion_table.items():
            dna = dna.replace(value, key)
        return dna

    def decode(self, input_file: str) -> list[int]:
        """Decode the data from a file.

        Args:
            input_file (str): File to read the encoded data from.

        Returns:
            list[int]: Decoded data.
        """
        # check if the file exists
        if not os.path.isfile(input_file):
            self.logger.warning(f"{input_file}: Not a file")
            return []
        data = self.read_file(os.path.abspath(input_file))
        data = "".join(data)
        data = data.split(">")
        data = [re.sub(r"(MSG\.\d*)", r"\1 ", i) for i in data]
        data = [i for i in data if i]
        data = sorted(data, key=lambda x: int(x.split(" ")[0].split(".")[1]))
        packets = []
        for line in data:
            if line.startswith("MSG."):
                (_, msg) = [item for item in line.split(" ") if item]
                buffer = self._to_hex(msg)
                packets.append(buffer)

        # find the length of the longest packet
        longest = max([len(packet) for packet in packets])

        # pad all packets to the length of the longest packet
        packets = [packet.ljust(longest, "-") for packet in packets]

        return packets

    @abstractmethod
    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        """Run the alignment algorithm."""
        pass

    def read_file(self, filename: str) -> list[str]:
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                return f.read().splitlines()
        else:
            self.logger.error(f"{filename}\t: Not a file")
