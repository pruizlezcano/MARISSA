import os
from abc import ABC, abstractmethod
from typing import List

import numpy as np
from sklearn.manifold import TSNE
from sklearn.metrics import (
    calinski_harabasz_score,
    davies_bouldin_score,
    silhouette_score,
)

from marissa.distance_metrics import DistanceAlgorithm
from marissa.Logger import Logger


class ClusterAlgorithm(ABC):
    def __init__(self, data, distance_algorithm: DistanceAlgorithm):
        self.logger = Logger()
        self.distance_algorithm = distance_algorithm
        self.data = data
        self.distances = self.calculate_distance_matrix(data)

    def calculate_distance_matrix(self, data: List[str]) -> np.ndarray:
        """Calculate the distance matrix between all data points.

        Args:
            data (List[str]): List of data points.

        Returns:
            np.ndarray: Distance matrix.
        """

        # Pre-calculate nodes once
        nodes = [self.distance_algorithm.calculate_node(i) for i in data]
        n = len(nodes)
        distances = np.zeros((n, n))

        # Only calculate upper triangle since distance matrix is usually symmetric
        for i in range(n):
            # Diagonal is usually 0 for distance metrics
            for j in range(i + 1, n):
                distance = self.distance_algorithm.compare(nodes[i], nodes[j])
                distances[i, j] = distance
                distances[j, i] = distance  # Mirror the value

        return distances

    def calculate_silhouette_score(self, clusters: List[str]) -> float:
        """Calculate the silhouette score of the clustering.

        Args:
            clusters (List[str]): List of clusters.

        Returns:
            float: Silhouette score.
        """
        return silhouette_score(self.distances, clusters)

    def calculate_davies_bouldin_score(self, clusters: List[str]) -> float:
        """Calculate the Davis-Bouldin index of the clustering.

        Args:
            clusters (List[List[int]]): List of clusters.

        Returns:
            float: Davis-Bouldin index.
        """
        return davies_bouldin_score(self.distances, clusters)

    def calculate_calinski_harabasz_score(self, clusters: List[str]) -> float:
        """Calculate the Calinski-Harabasz index of the clustering.

        Args:
            clusters (List[List[int]]): List of clusters.

        Returns:
            float: Calinski-Harabasz index.
        """
        return calinski_harabasz_score(self.distances, clusters)

    @abstractmethod
    def perform_clustering(self) -> List[int]:
        """Perform clustering on the data."""
        pass
