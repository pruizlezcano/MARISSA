import os
import re
from abc import ABC, abstractmethod

from marissa.Logger import Logger


class AlignmentAlgorithm(ABC):
    def __init__(self):
        self.logger = Logger()

    def to_dna_sequence(self, item):
        conversion_table = {"00": "A", "01": "T", "10": "G", "11": "C"}
        ret = ""

        for byte in item:
            bites = f"{byte:08b}"
            ret += conversion_table[bites[0:2]]
            ret += conversion_table[bites[2:4]]
            ret += conversion_table[bites[4:6]]
            ret += conversion_table[bites[6:8]]

        return ret

    def encode(self, data, output_file: str) -> list[int]:
        """Encode the data to a file.

        Args:
            data (list[str]): Data to encode.
            output_file (str): File to write the encoded data to.
        """
        max_len = 0

        with open(output_file, "w") as f:
            for i, item in enumerate(data):
                bytes_ = bytes.fromhex(item)
                dna_sequence = self.to_dna_sequence(bytes_)
                f.write(f">MSG.{i:0{len(str(len(data)))}}\n")

                if max_len < len(dna_sequence):
                    max_len = len(dna_sequence)

                f.write(f"{dna_sequence}\n")

    def convert_bits(self, bits):
        conversion_table = {"A": "00", "T": "01", "G": "10", "C": "11"}
        bits_str = "".join(
            [conversion_table[x] for x in bits.upper() if x in conversion_table]
        )
        if bits_str == "":
            return "-"
        byte_ = int(bits_str, 2)
        return byte_

    def to_bytes(self, sequence):
        ret = []
        indexes = list(range(0, len(sequence), 4))
        last_index = indexes.pop(0)

        for index in indexes:
            bits = sequence[last_index:index]
            last_index = index
            bits = bits.replace("-", "")
            byte_ = self.convert_bits(bits)
            if byte_ == "-":
                ret.append("--")
            else:
                ret.append(format(byte_, "x").zfill(2))

        bits = sequence[last_index:]
        byte_ = self.convert_bits(bits)
        if byte_ == "-":
            ret.append("--")
        else:
            ret.append(format(byte_, "x").zfill(2))

        return "".join(ret)

    def decode(self, input_file: str) -> list[int]:
        """Decode the data from a file.

        Args:
            input_file (str): File to read the encoded data from.

        Returns:
            list[int]: Decoded data.
        """
        data = self.read_file(os.path.abspath(input_file))
        data = "".join(data)
        data = data.split(">")
        data = [re.sub(r"(MSG\.\d*)", r"\1 ", i) for i in data]
        data = [i for i in data if i]
        data = sorted(data, key=lambda x: int(x.split(" ")[0].split(".")[1]))
        packets = []
        for line in data:
            if line.startswith("MSG."):
                (msg_id, msg) = [item for item in line.split(" ") if item]
                msg_copy = msg.replace("-", "")
                buffer = self.to_bytes(msg)
                buffer_copy = self.to_bytes(msg_copy)
                # it aligns bits so the byte can be cut in half so we use two arrays to convert it back to hexadecimal
                # One knows where the dashes are and the other knows the correct hexadecimal
                # TODO: this code works but it's not very readable
                i_copy = 0
                for i in range(len(buffer)):
                    if buffer[i] == "-":
                        mult = 1
                        if i + 1 < len(buffer):
                            mult = 3 if buffer[i + 1] != "-" else 1
                            if buffer[i + 1] != "-":
                                mult += (
                                    2
                                    if buffer_copy[i : i + 2] not in buffer[i : i + 5]
                                    else 0
                                )
                        buffer_copy = buffer_copy[:i] + "-" * mult + buffer_copy[i:]
                    i_copy += 1
                packets.append(buffer_copy)

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
