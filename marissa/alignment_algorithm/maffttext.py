import os

from marissa.alignment_algorithm import AlignmentAlgorithm


class MafftTextAlgorithm(AlignmentAlgorithm):

    def __init__(self):
        super().__init__()

    def encode(self, data, output_file: str) -> list[int]:
        with open(output_file, "w") as f:
            for i, item in enumerate(data):
                f.write(f">MSG.{i:0{len(str(len(data)))}}\n")
                f.write(f"{item}\n")

    def decode(self, input_file: str) -> list[int]:
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

        # find the length of the longest packet
        longest = max([len(packet) for packet in packets])

        # pad all packets to the length of the longest packet
        packets = [packet.ljust(longest, "-") for packet in packets]

        return packets

    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        os.system(
            f"mafft --text {'--quiet' if not verbose else ''} {input_file} > {output_file}"
        )
