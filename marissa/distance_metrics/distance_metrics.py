from abc import ABC, abstractmethod


class DistanceAlgorithm(ABC):
    @classmethod
    @abstractmethod
    def compare(cls, a: str, b: str) -> float:
        """Compare two data points.

        Args:
            a (str): Data point a.
            b (str): Data point b.

        Returns:
            float: Distance between the two data points.
        """
        pass

    @classmethod
    def calculate_node(cls, a: str) -> str:
        """Calculate the node.

        Args:
            a (str): Data to calculate the node for.

        Returns:
            str: Converted data.
        """
        return a
