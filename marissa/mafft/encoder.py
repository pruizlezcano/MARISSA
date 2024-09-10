#!/usr/bin/env python3

import os
import sys


def main(data, output):
    with open(output, "w") as f:
        for i, item in enumerate(data):
            f.write(f">MSG.{i:0{len(str(len(data)))}}\n")
            f.write(f"{item}\n")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        print(f"usage\t: {os.path.basename(__file__)} <file> <output>", file=sys.stderr)
        sys.exit(-1)
