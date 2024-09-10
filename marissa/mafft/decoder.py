import os


def read_file(filename):
    if os.path.isfile(filename):
        with open(filename, "r") as f:
            return f.read().splitlines()
    else:
        print(f"[-] {os.path.basename(__file__)}\t: ERROR\t: {filename}\t: Not a file")


def main(filename):
    if not os.path.isfile(filename):
        print(f"[-] {os.path.basename(__file__)}\t: ERROR\t: {filename}\t: Not a file")
        return
    data = read_file(os.path.abspath(filename))
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
