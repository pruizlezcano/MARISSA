import os
from typing import List

from marissa.alignment_algorithm import AlignmentAlgorithm


class MafftTextAlgorithm(AlignmentAlgorithm):

    def __init__(self):
        super().__init__()

    def encode(self, data, output_file: str) -> List[int]:
        with open(output_file, "w") as f:
            for i, item in enumerate(data):
                f.write(f">MSG.{i:0{len(str(len(data)))}}\n")
                f.write(f"{AlignmentAlgorithm._add_byte_separators(item)}\n")

    def decode(self, input_file: str) -> List[int]:
        data = self.read_file(os.path.abspath(input_file))
        packets = []
        packet = ""
        for line in data[1:]:
            if line.startswith(">MSG."):
                packets.append(packet)
                packet = ""
            else:
                packet += line
        packets.append(packet)

        # Initial padding to make all packets the same length
        packets = self._pad_packets(packets)

        packets = self._remove_characters(packets)

        # After removing characters, ensure all have same final length
        packets = self._pad_packets(packets)
        return packets

        return packets

    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        os.system(
            f"mafft --text {'--quiet' if not verbose else ''} {input_file} > {output_file}"
        )
