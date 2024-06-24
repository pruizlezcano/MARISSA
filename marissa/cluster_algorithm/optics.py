from sklearn.cluster import OPTICS

from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.distance_metrics import DistanceAlgorithm


class OpticsAlgorithm(ClusterAlgorithm):

    def __init__(self, data, distance_algorithm: DistanceAlgorithm):
        super().__init__(data, distance_algorithm)

    def perform_clustering(self):
        """Perform OPTICS clustering on the data."""
        clustering = OPTICS().fit_predict(self.distances)

        return clustering
