from typing import List


def _has_even_bytes(fields: List[str]) -> bool:
    """Check if the fields have even bytes.

    Args:
        fields (List[str]): List of fields

    Returns:
        bool: True if has even bytes, False otherwise
    """
    for i in fields:
        if len(i) % 2 != 0:
            return False
    return True


def _is_variable_field(fields: List[str]) -> bool:
    """Check if the field is variable.

    Args:
        fields (List[str]): List of fields

    Returns:
        bool: True if variable, False otherwise
    """
    for i in fields:
        if "-" in i:
            return True
    return False


def find_fields(packets: List[str]) -> list:
    """Find fields in the packets.

    Args:
        packets (List[str]): List of packets

    Returns:
        list: List of fields
    """
    message_length = len(max(packets, key=len))
    results_fields = []
    i = 0
    isLastStatic = False
    while i < message_length:
        offset = 2
        start_pos = i
        while i + offset <= message_length:
            field = [packet[i : i + offset] for packet in packets]
            if not _has_even_bytes(field):
                offset += 1
                continue
            else:
                break
        if not len(set(field)) == 1:
            if _is_variable_field(field):
                fields_info = [start_pos, offset, "V"]
            else:
                fields_info = [start_pos, offset, "D"]
            results_fields.append(fields_info)
            isLastStatic = False
        else:
            if isLastStatic:
                results_fields[-1][1] += offset
            else:
                fields_info = [start_pos, offset, "S"]
                results_fields.append(fields_info)
            isLastStatic = True

        i += offset

    return results_fields
