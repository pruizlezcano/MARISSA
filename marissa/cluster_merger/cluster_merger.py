from abc import ABC, abstractmethod
from typing import Tuple

from pandas import DataFrame

from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.distance_metrics import DistanceAlgorithm
from marissa.Logger import Logger


class ClusterMerger(ABC):
    def __init__(
        self,
        cluster_algorithm: ClusterAlgorithm = None,
        distance_algorithm: DistanceAlgorithm = None,
    ):
        self.logger = Logger()
        self.cluster_algorithm = cluster_algorithm
        self.distance_algorithm = distance_algorithm

    @abstractmethod
    def merge(
        self,
        df: DataFrame,
        threshold: float = None,
    ) -> Tuple[DataFrame, bool]:
        """Merge clusters based on some criteria.

        Args:
            df (DataFrame): Marissa DataFrame.

        Returns:
            Set[DataFrame, bool]: Merged DataFrame and a boolean indicating if the DataFrame needs alignment.
        """
        pass
