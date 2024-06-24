import numpy as np
from kneed import KneeLocator
from sklearn.cluster import KMeans

from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.distance_metrics import DistanceAlgorithm


class KMeansHierarchicalAlgorithm(ClusterAlgorithm):

    def __init__(self, data, distance_algorithm: DistanceAlgorithm):
        super().__init__(data, distance_algorithm)

    def perform_clustering(self):
        """Perform KMeans clustering on the data."""
        n_clusters = self.calculate_optimal_clusters(self.distances)
        clusters = list(range(len(self.data)))
        clustering = KMeans(
            n_clusters=n_clusters, init="random", max_iter=1000, random_state=0
        ).fit_predict(self.distances)

        for i in range(0, n_clusters):
            # Get the indices of the data points that belong to the current cluster
            cluster_indices = [j for j in range(len(clustering)) if clustering[j] == i]
            # Get the data points that belong to the current cluster
            cluster = [self.data[j] for j in cluster_indices]
            cluster_distances = self.calculate_distance_matrix(cluster)
            n_sub_clusters = self.calculate_optimal_clusters(cluster_distances)
            if n_sub_clusters is None:
                continue
            sub_clustering = KMeans(
                n_clusters=n_sub_clusters, init="random", max_iter=1000, random_state=0
            ).fit_predict(cluster_distances)
            # Update the clustering with the sub-clustering
            for j in range(len(cluster_indices)):
                clusters[cluster_indices[j]] = f"{i}s{sub_clustering[j]}"
        return clusters

    def calculate_optimal_clusters(self, distances: np.ndarray) -> int:
        """Calculate the optimal number of clusters using the knee method.

        Args:
            distances (np.ndarray): Distance matrix.

        Returns:
            int: Optimal number of clusters.
        """
        y = []
        max_clusters = min(10, len(distances))
        for i in range(1, max_clusters):
            kmeans = KMeans(n_clusters=i, init="random", max_iter=1000, random_state=0)
            kmeans.fit(distances)
            y.append(kmeans.inertia_)
        x = range(1, len(y) + 1)
        kn = KneeLocator(x, y, curve="convex", direction="decreasing")
        return kn.knee
