import os
import re
from abc import ABC, abstractmethod
from typing import List

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
    """Abstract class for alignment algorithms."""

    def __init__(self):
        self.logger = Logger()

    @staticmethod
    def _add_byte_separators(item: str, separator: str = "~") -> str:
        """Add separators between each pair of characters (representing bytes).

        Args:
            item (str): String to add separators to.
            separator (str, optional): Character to use as separator. Defaults to "~".

        Returns:
            str: String with separators added between byte pairs.
        """
        result = ""
        for i in range(0, len(item), 2):
            if i + 1 < len(item):
                result += item[i] + item[i + 1]
                if i + 2 < len(item):  # Don't add separator after the last byte
                    result += separator
            else:
                result += item[i]  # Handle odd-length strings
        return result

    @staticmethod
    def _to_dna_sequence(item: str) -> str:
        """Convert an item to a DNA sequence.

        Args:
            item (str): Hexadecimal string to convert.

        Returns:
            str: DNA sequence.
        """
        item = item.upper()
        for key, value in conversion_table.items():
            item = item.replace(key, value)
        return AlignmentAlgorithm._add_byte_separators(item)

    def encode(self, data: List[str], output_file: str):
        """Encode the data to a file.

        Args:
            data (List[str]): Data to encode.
            output_file (str): File to write the encoded data to.
        """
        with open(output_file, "w") as f:
            for i, item in enumerate(data):
                dna_sequence = self._to_dna_sequence(item)
                f.write(f">MSG.{i:0{len(str(len(data)))}}\n")

                f.write(f"{dna_sequence}\n")

    @staticmethod
    def _remove_characters(data: List[str]) -> List[str]:
        """Remove columns that contain only padding characters across all packets.

        This function examines each position/column across all packets and removes
        positions where every packet has only a padding character ('-' or '~').
        This is useful for removing alignment gaps that don't contain any actual data.

        Args:
            data (List[str]): List of aligned packets with padding

        Returns:
            List[str]: List of packets with unnecessary padding columns removed
        """
        res = [list() for i in range(len(data))]
        for i in range(len(data[0])):
            isToDelete = True
            for line in data:
                if line[i] != "-" and line[i] != "~":
                    isToDelete = False
                    break
            if not isToDelete:
                for j, line in enumerate(data):
                    res[j].append(line[i])
        res = ["".join(line) for line in res]
        return res

    @staticmethod
    def _to_hex(dna: str) -> str:
        """Convert a DNA sequence to hexadecimal.

        Args:
            dna (str): DNA sequence to convert.

        Returns:
            str: Hexadecimal string.
        """
        dna = dna.replace("~", "").upper()
        for key, value in conversion_table.items():
            dna = dna.replace(value, key)
        return dna

    @staticmethod
    def _pad_packets(packets: List[str], pad_char: str = "-") -> List[str]:
        """Pad all packets to the length of the longest packet.

        Args:
            packets (List[str]): List of packets to pad
            pad_char (str, optional): Character to use for padding. Defaults to "-".

        Returns:
            List[str]: List of padded packets with uniform length
        """
        if not packets:
            return []

        longest = max([len(packet) for packet in packets])
        return [packet.ljust(longest, pad_char) for packet in packets]

    def decode(self, input_file: str) -> List[str]:
        """Decode the data from a file.

        Args:
            input_file (str): File to read the encoded data from.

        Returns:
            List[str]: Decoded data.
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
        packets: List[str] = []
        for line in data:
            if line.startswith("MSG."):
                (_, msg) = [item for item in line.split(" ") if item]
                buffer = self._to_hex(msg)
                packets.append(buffer)

        packets = self._pad_packets(packets)

        return packets

    @abstractmethod
    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        """Run the alignment algorithm."""
        pass

    def read_file(self, filename: str) -> List[str]:
        """Read a file

        Args:
            filename (str): Path to the file.

        Returns:
            List[str]: List of lines in the file.
        """
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                return f.read().splitlines()
        else:
            self.logger.error(f"{filename}\t: Not a file")
