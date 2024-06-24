import tlsh

from marissa.distance_metrics import DistanceAlgorithm


class TLSHDistance(DistanceAlgorithm):
    def compare(cls, a: str, b: str) -> float:
        return tlsh.diff(a, b)

    def calculate_node(cls, a: str) -> int:
        return tlsh.hash(a.encode("utf-8"))
