import json
import os
from typing import List


def parse_tshark_pairs(packet: List[tuple]) -> dict:
    # change the name of duplicated keys, add a number to the end
    dict = {}
    for pair in packet:
        key = pair[0]
        value = pair[1]
        if key in dict:
            i = 1
            while f"{key}_{i}" in dict:
                i += 1
            key = f"{key}_{i}"
        dict[key] = value
    return dict


def run_tshark(pcap_path: str) -> dict:
    output_path = pcap_path.replace(".pcap", ".json")
    os.system(f"tshark -r {pcap_path} -T json --hexdump frames > {output_path}")
    with open(output_path) as f:
        return json.load(f, object_pairs_hook=parse_tshark_pairs)
