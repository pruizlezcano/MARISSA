#!/usr/bin/env python3

import os
import sys

conversion_table = {"00": "A", "01": "T", "10": "G", "11": "C"}


def to_dna_sequence(item):
    ret = ""

    for byte in item:
        bites = f"{byte:08b}"
        ret += conversion_table[bites[0:2]]
        ret += conversion_table[bites[2:4]]
        ret += conversion_table[bites[4:6]]
        ret += conversion_table[bites[6:8]]

    return ret


def main(data, output):
    max_len = 0

    with open(output, "w") as f:
        for i, item in enumerate(data):
            bytes_ = bytes.fromhex(item)
            dna_sequence = to_dna_sequence(bytes_)
            f.write(f">MSG.{i:0{len(str(len(data)))}}\n")

            if max_len < len(dna_sequence):
                max_len = len(dna_sequence)

            f.write(f"{dna_sequence}\n")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        print(f"usage\t: {os.path.basename(__file__)} <file> <output>", file=sys.stderr)
        sys.exit(-1)
