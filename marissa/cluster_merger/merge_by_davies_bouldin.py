from typing import Tuple

from pandas import DataFrame

from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.cluster_merger import ClusterMerger
from marissa.distance_metrics import DistanceAlgorithm


class MergeByDaviesBouldin(ClusterMerger):
    def __init__(
        self,
        cluster_algorithm: ClusterAlgorithm,
        distance_algorithm: DistanceAlgorithm,
    ):
        super().__init__(cluster_algorithm, distance_algorithm)

    def merge(
        self,
        df: DataFrame,
        threshold=None,
    ) -> Tuple[DataFrame, bool]:
        self.logger.info("Merging clusters by Davis-Bouldin index")
        need_realignment = False
        for cluster_id, cluster_packets in df.groupby("cluster"):
            for other_cluster_id, other_cluster_packets in df.groupby("cluster"):
                if str(other_cluster_id) == str(cluster_id):
                    continue

                clusterizer = self.cluster_algorithm(
                    cluster_packets["hex"].to_list()
                    + other_cluster_packets["hex"].to_list(),
                    self.distance_algorithm,
                )

                score = clusterizer.calculate_davies_bouldin_score(
                    cluster_packets["cluster"].to_list()
                    + other_cluster_packets["cluster"].to_list()
                )

                self.logger.debug(
                    f"Cluster {cluster_id} vs {other_cluster_id}: {score}"
                )

                if abs(score) < threshold:
                    need_realignment = True
                    df.loc[df["cluster"] == other_cluster_id, "cluster"] = [
                        cluster_id
                    ] * len(df.loc[df["cluster"] == other_cluster_id])

        return df, need_realignment
