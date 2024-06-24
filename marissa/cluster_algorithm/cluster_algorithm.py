from abc import ABC, abstractmethod
from typing import List

import numpy as np
from matplotlib import pyplot as plt
from matplotlib.patches import Patch
from sklearn.manifold import TSNE

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
        self.logger.debug("Calculating distance matrix...")
        distances = np.zeros((len(data), len(data)))
        for i in range(len(data)):
            for j in range(len(data)):
                distances[i, j] = self.distance_algorithm.compare(data[i], data[j])
        return distances

    @abstractmethod
    def perform_clustering(self):
        """Perform clustering on the data."""
        pass

    def plot(self, clusters: np.ndarray) -> None:
        """Plot the clusters in a 2D space.

        Args:
            clusters (np.ndarray): Clusters to plot.
        """
        tsne = TSNE(n_components=2, random_state=0)
        points = tsne.fit_transform(self.distances)
        # Set figure size to be large, which should fill most screens.
        fig, ax = plt.subplots(figsize=(16, 9))  # 16x9 aspect ratio, adjust as needed
        # Convert clusters to unique integers
        unique_clusters = list(set(clusters))
        cluster_colors = [unique_clusters.index(cluster) for cluster in clusters]

        # Normalize the cluster colors
        norm = plt.Normalize(min(cluster_colors), max(cluster_colors))

        ax.scatter(
            points[:, 0],
            points[:, 1],
            c=cluster_colors,
            s=50,
            cmap="viridis",
            norm=norm,
        )

        # Create a custom legend
        legend_elements = [
            Patch(facecolor=plt.cm.viridis(norm(i)), label=cluster)
            for i, cluster in enumerate(unique_clusters)
        ]
        fig.legend(
            handles=legend_elements,
            title="Clusters",
            loc="outside upper right",
            # ncols=3,
        )
        plt.show()
