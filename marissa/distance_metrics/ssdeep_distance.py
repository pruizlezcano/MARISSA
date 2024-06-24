import ssdeep

from marissa.distance_metrics import DistanceAlgorithm


class SSDEEPDistance(DistanceAlgorithm):
    def compare(cls, a: str, b: str) -> float:
        return ssdeep.compare(a, b)

    def calculate_node(cls, a: str) -> str:
        return ssdeep.hash(a)
