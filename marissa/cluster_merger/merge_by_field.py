from typing import Tuple

from pandas import DataFrame

from marissa.cluster_merger import ClusterMerger


class MergeByField(ClusterMerger):
    def __init__(self):
        super().__init__()

    def merge(
        self,
        df: DataFrame,
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

            cluster_packets["static"] = cluster_packets["aligned"].apply(
                lambda x: x[static_field[0] : static_field[0] + static_field[1]]
            )

            static_field_content = cluster_packets["static"].value_counts().idxmax()

            if len(static_field_content) == 0:
                static_field_content = cluster_packets["static"].value_counts().idxmax()

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

                other_cluster_packets["static"] = other_cluster_packets[
                    "aligned"
                ].apply(
                    lambda x: x[
                        other_static_field[0] : other_static_field[0]
                        + other_static_field[1]
                    ]
                )

                other_static_field_content = (
                    other_cluster_packets["static"].value_counts().idxmax()
                )

                length = min(static_field[1], other_static_field[1], 6)

                is_same_field = (
                    static_field_content[0:length]
                    == other_static_field_content[0:length]
                    and static_field[0] == other_static_field[0]
                )
                if is_same_field:
                    need_realignment = True
                    df.loc[df["cluster"] == other_cluster_id, "cluster"] = [
                        cluster_id
                    ] * len(df.loc[df["cluster"] == other_cluster_id])

        return df, need_realignment
