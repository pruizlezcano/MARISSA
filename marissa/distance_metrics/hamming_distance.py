from marissa.distance_metrics import DistanceAlgorithm


class HammingDistance(DistanceAlgorithm):
    def compare(cls, a: str, b: str) -> float:
        return sum(c1 != c2 for c1, c2 in zip(a, b))
