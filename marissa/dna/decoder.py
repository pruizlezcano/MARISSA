import os

conversion_table = {"A": "00", "T": "01", "G": "10", "C": "11"}


def convert_bits(bits):
    bits_str = "".join(
        [conversion_table[x] for x in bits.upper() if x in conversion_table]
    )
    if bits_str == "":
        return "-"
    byte_ = int(bits_str, 2)
    return byte_


def to_bytes(sequence):
    ret = []
    indexes = list(range(0, len(sequence), 4))
    last_index = indexes.pop(0)

    for index in indexes:
        bits = sequence[last_index:index]
        last_index = index
        bits = bits.replace("-", "")
        byte_ = convert_bits(bits)
        if byte_ == "-":
            ret.append("--")
        else:
            ret.append(format(byte_, "x").zfill(2))

    bits = sequence[last_index:]
    byte_ = convert_bits(bits)
    if byte_ == "-":
        ret.append("--")
    else:
        ret.append(format(byte_, "x").zfill(2))

    return "".join(ret)


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
    for line in data:
        if line.startswith("MSG."):
            (msg_id, msg) = [item for item in line.split(" ") if item]
            msg_copy = msg.replace("-", "")
            buffer = to_bytes(msg)
            buffer_copy = to_bytes(msg_copy)
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
