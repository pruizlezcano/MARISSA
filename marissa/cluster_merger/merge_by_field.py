from typing import Tuple

from pandas import DataFrame

from marissa.cluster_merger import ClusterMerger


class MergeByField(ClusterMerger):
    def __init__(self):
        super().__init__()

    def merge(
        self,
        df: DataFrame,
        threshold: float = None,
    ) -> Tuple[DataFrame, bool]:
        self.logger.info("Merging clusters with the same field")
        need_realignment = False
        for cluster_id, cluster_packets in df.groupby("cluster"):
            if len(cluster_packets) == 1:
                continue
            fields = cluster_packets["fields"].iloc[0]
            static_fields = [i for i in fields if i[2] == "S"]
            if len(static_fields) == 0:
                continue
            else:
                static_field = static_fields[0]

            length = min(6, static_field[1])
            static_field_content = cluster_packets["aligned"].iloc[0][
                static_field[0] : static_field[0] + length
            ]

            for other_cluster_id, other_cluster_packets in df.groupby("cluster"):
                if str(other_cluster_id) == str(cluster_id):
                    continue
                # check if the other cluster has the same static field
                other_fields = other_cluster_packets["fields"].iloc[0]
                other_static_fields = [i for i in other_fields if i[2] == "S"]
                if len(other_static_fields) == 0:
                    continue
                else:
                    other_static_field = other_static_fields[0]

                other_static_field_content = other_cluster_packets["aligned"].iloc[0][
                    other_static_field[0] : other_static_field[0]
                    + other_static_field[1]
                ]

                length = min(length, other_static_field[1])

                is_same_field = (
                    static_field_content[0:length]
                    == other_static_field_content[0:length]
                )
                if is_same_field:
                    need_realignment = True
                    df.loc[df["cluster"] == other_cluster_id, "cluster"] = [
                        cluster_id
                    ] * len(df.loc[df["cluster"] == other_cluster_id])

        return df, need_realignment
