import json
import os
from typing import List

import pandas as pd

from marissa.alignment_algorithm import AlignmentAlgorithm
from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.cluster_merger import ClusterMerger
from marissa.cluster_merger.merge_by_field import MergeByField
from marissa.distance_metrics import DistanceAlgorithm
from marissa.Logger import Logger
from marissa.pcap import Pcap
from marissa.utils import find_fields, remove_files


class Marissa:
    """Main class for the Marissa tool."""

    def __init__(
        self,
        verbose=False,
        packet_length: int = None,
        packet_length_variance: int = None,
        percent_equal: int = 1,
        input_file=None,
        output=None,
        remove_headers: bool = False,
        distance_algorithm: DistanceAlgorithm = None,
        cluster_algorithm: ClusterAlgorithm = None,
        cluster_merger: ClusterMerger = None,
        merge_threshold: float = None,
        align_algorithm: AlignmentAlgorithm = None,
        group_by_ethernet: bool = False,
        remove_duplicates: bool = False,
    ):
        """Initialize the Marissa class.

        Args:
            verbose (bool, optional): Print debug statements. Defaults to False.
            packet_length (int, optional): Filter packets by given length. Defaults to None.
            packet_length_variance (int, optional): Allowed variance in packet length for filtering. Defaults to None.
            percent_equal (int, optional): Minimum percentage of packets that must be equal for clustering. Defaults to 1.
            input_file (str, optional): Input .pcap file path. Defaults to None.
            output (str, optional): Path of the directory to write the results to. Defaults to None.
            remove_headers (bool, optional): Should remove the message headers. Defaults to False.
            distance_algorithm (DistanceAlgorithm, optional): Algorithm to calculate distance between packets. Defaults to None.
            cluster_algorithm (ClusterAlgorithm, optional): Algorithm to cluster packets. Defaults to None.
            align_algorithm (AlignmentAlgorithm, optional): Algorithm to align packets. Defaults to None.
            group_by_ethernet (bool, optional): Group packets by Ethernet header. Defaults to False.
            remove_duplicates (bool, optional): Remove duplicate packets. Defaults to False.
        """
        self.input_file = input_file
        self.output_path = output
        self.max_length: int
        self.verbose = verbose
        self.packet_length = packet_length
        self.packet_length_variance = packet_length_variance
        self.percent_equal = percent_equal
        self.remove_headers = remove_headers
        self.clusters: list[str]
        self.logger = Logger(verbose)
        self.distance_algorithm: DistanceAlgorithm = distance_algorithm()
        self.cluster_algorithm: ClusterAlgorithm = cluster_algorithm
        self.merger_algorithm: ClusterMerger = cluster_merger
        self.merge_threshold = merge_threshold
        self.align_algorithm: AlignmentAlgorithm = align_algorithm()
        self.group_by_ethernet = group_by_ethernet
        self.remove_duplicates = remove_duplicates
        self.df: pd.DataFrame
        self.running_time: pd.Timedelta

    def prepare(self):
        """Prepare the data for the clustal test."""
        self.load_data()
        self.df = self.df.head(1000)
        if self.packet_length is not None:
            self.filter_data_by_packet_length()
        if self.remove_headers:
            self.remove_header()
        if self.remove_duplicates:
            self.remove_duplicate_packets()
        self.df = self.df.dropna()
        self.max_length = max(self.df["length"])
        self.clusterize()

    def load_data(self):
        """Load data from input file and calculate necessary features."""
        self.logger.debug("Loading data from input file")
        packets = Pcap.load(self.input_file)
        self.logger.info(f"Loaded {len(packets)} packets")
        self.df = pd.DataFrame([i for i in packets], columns=["raw"])
        self.df["hex"] = self.df["raw"].apply(str)
        self.df["original"] = self.df["hex"]
        self.df["length"] = self.df["hex"].apply(lambda x: len(x) // 2)
        self.df["id"] = self.df.index + 1
        if self.group_by_ethernet:
            self.df["ethernet"] = self.df["hex"].apply(lambda x: x[:24])

    def filter_data_by_packet_length(self):
        """Filter data by packet length if packet_length is specified."""
        self.logger.debug("Filtering data by packet length")
        if self.packet_length is not None:
            self.df = self.df[
                (self.df["length"] >= self.packet_length - self.packet_length_variance)
                & (
                    self.df["length"]
                    <= self.packet_length + self.packet_length_variance
                )
            ]
        self.logger.info(f"{len(self.df)} packets remain after filtering by length")

    def remove_header(self):
        """Add header length to raw data if header_length is specified."""
        self.logger.debug("Removing headers from data")
        self.df["hex"] = [x.get_applayer() for x in self.df["raw"]]

    def remove_duplicate_packets(self):
        """Remove duplicate packets from the data."""
        self.logger.debug("Removing duplicate packets")
        self.df = self.df.drop_duplicates("hex")
        self.df = self.df.reset_index(drop=True)
        self.logger.info(f"{len(self.df)} packets remain after removing duplicates")

    def clusterize(self):
        """Clusterize the messages."""
        self.logger.debug("Performing clustering...")
        if self.group_by_ethernet:
            # get groups of packets with the same ethernet header
            self.df["group"] = self.df.groupby("ethernet").ngroup()

            for group_id, group_packets in self.df.groupby("group"):
                clusterizer = self.cluster_algorithm(
                    group_packets["hex"], self.distance_algorithm
                )
                self.df.loc[self.df["group"] == group_id, "cluster"] = list(
                    map(lambda x: f"{group_id}s{x}", clusterizer.perform_clustering())
                )
        else:
            clusterizer = self.cluster_algorithm(
                self.df["hex"], self.distance_algorithm
            )
            self.df["cluster"] = list(
                map(lambda x: f"{x}", clusterizer.perform_clustering())
            )

        self.clusters = self.df["cluster"].unique()
        self.logger.info(f"Clustering done. Found {len(self.clusters)} clusters")
        self.df["id_cluster"] = self.df.groupby("cluster").cumcount()

    def encode_data(self):
        """Encode the data and save it to a file."""
        for cluster_id, cluster_packets in self.df.groupby("cluster"):
            self.align_algorithm.encode(
                cluster_packets["hex"],
                os.path.join(self.output_path, f"input.{cluster_id}.fasta"),
            )

    def run(self):
        """Run the MARISSA analysis."""
        self.encode_data()
        self.logger.info("Aligning data")
        for cluster_id in self.clusters:
            self.logger.debug(f"Running aligment for cluster {cluster_id}")
            self.align_algorithm.run(
                self.verbose,
                os.path.join(self.output_path, f"input.{cluster_id}.fasta"),
                os.path.join(self.output_path, f"output.{cluster_id}.clustal_num"),
            )

    def post_run(self):
        """Post run actions"""
        self.decode_aligned_data()
        if len(self.clusters) > 2 and self.merger_algorithm is not None:
            if self.merger_algorithm == MergeByField:
                self.get_fields()
            if self.merger_algorithm == MergeByField:
                merger_algorithm = self.merger_algorithm()
            else:
                merger_algorithm = self.merger_algorithm(
                    self.cluster_algorithm, self.distance_algorithm
                )
            self.df, need_realignment = merger_algorithm.merge(
                df=self.df, threshold=self.merge_threshold
            )
            if need_realignment:
                new_clusters = self.df["cluster"].unique()
                for cluster_id in self.clusters:
                    if cluster_id not in new_clusters:
                        remove_files(
                            [
                                os.path.join(
                                    self.output_path, f"input.{cluster_id}.fasta"
                                ),
                                os.path.join(
                                    self.output_path, f"output.{cluster_id}.clustal_num"
                                ),
                            ]
                        )
                self.clusters = self.df["cluster"].unique()
                self.df["id_cluster"] = self.df.groupby("cluster").cumcount()
                self.logger.info(f"Merging done, {len(self.clusters)} clusters remain")
                self.run()
                self.post_run()

    def decode_aligned_data(self):
        """Decode aligned data for each cluster."""
        self.logger.info("Decoding aligned data")
        for cluster_id in self.clusters:
            self.logger.debug(f"Decoding aligned data for cluster {cluster_id}")
            data_aligned = self.align_algorithm.decode(
                os.path.join(self.output_path, f"output.{cluster_id}.clustal_num")
            )
            if len(data_aligned) == 0:
                self.logger.warning(
                    f"Cluster {cluster_id} has no aligned data. Skipping..."
                )
                self.df = self.df[self.df["cluster"] != cluster_id]
                continue
            self.df.loc[self.df["cluster"] == cluster_id, "aligned"] = data_aligned

    def get_fields(self):
        """Get fields for each cluster."""
        self.logger.info("Getting fields for each cluster")

        if "fields" not in self.df.columns:
            self.df["fields"] = None

        for cluster_id, cluster_packets in self.df.groupby("cluster"):
            self.logger.debug(f"Finding fields for cluster {cluster_id}")
            fields = find_fields(cluster_packets["aligned"])
            self.df.loc[self.df["cluster"] == cluster_id, "fields"] = self.df.loc[
                self.df["cluster"] == cluster_id, "fields"
            ].apply(lambda x: fields)

    def cleanup(self):
        """Cleanup the files"""
        self.logger.debug("Cleaning up files")
        for cluster_id in self.clusters:
            remove_files(
                [
                    os.path.join(self.output_path, f"input.{cluster_id}.fasta"),
                    os.path.join(self.output_path, f"output.{cluster_id}.clustal_num"),
                ]
            )

    def save(self):
        """Save the results"""
        # Rename the cluster ids to be sequential
        # self.df["cluster"] = pd.Categorical(self.df["cluster"]).codes
        self.clusters = self.df["cluster"].unique()
        self.get_fields()
        self.save_results_to_file()
        self.save_cluster_data_to_pcap()
        self.df.to_csv(
            os.path.join(self.output_path, "output.csv"),
            index=False,
            columns=["cluster", "id_cluster", "raw", "aligned", "fields"],
        )
        self.save_meta()

    def save_meta(self):
        """Save metadata to a json file"""
        with open(os.path.join(self.output_path, "output.meta.json"), "w") as f:
            json.dump(
                {
                    "file": os.path.abspath(self.input_file),
                    "distance_algorithm": self.distance_algorithm.__class__.__name__,
                    "cluster_algorithm": self.cluster_algorithm.__qualname__,
                    "align_algorithm": self.align_algorithm.__class__.__name__,
                    "merge_algorithm": self.merger_algorithm.__qualname__,
                    "merge_threshold": self.merge_threshold,
                    "clusters": len(self.clusters),
                    "packet_count": len(self.df),
                    "remove_headers": self.remove_headers,
                    "remove_duplicates": self.remove_duplicates,
                    "group_by_ethernet": self.group_by_ethernet,
                    "running_time": self.running_time.total_seconds(),
                },
                f,
                indent=4,
            )

    def save_results_to_file(self):
        """Save results to a txt file"""
        self.logger.info("Saving results to file")
        with open(os.path.join(self.output_path, "output.txt"), "w") as f:
            f.write(
                f"File: {self.input_file} - Packets: {len(self.df)} - Max Length: {self.max_length}\n"
            )
            f.write(
                f"Distance Algorithm: {self.distance_algorithm.__class__.__name__} - "
            )
            f.write(f"Cluster Algorithm: {self.cluster_algorithm.__qualname__} - ")
            f.write(f"Align Algorithm: {self.align_algorithm.__class__.__name__}\n")
            f.write(f"Clusters: {len(self.clusters)}\n")
            f.write(
                f"\n* if all packets are equal\n. if at least {self.percent_equal*100}% of the packets are equal\n\n"
            )
            for cluster_id, cluster_packets in self.df.groupby("cluster"):
                self.write_cluster_data_to_file(f, cluster_id, cluster_packets)

    def write_cluster_data_to_file(self, f, cluster_id, cluster_packets):
        """Write data for a specific cluster to a file"""
        f.write(f"CLUSTER {cluster_id}:\n")
        id_length = max(len(str(x)) for x in cluster_packets["id_cluster"])
        for _, packet in cluster_packets.iterrows():  # Changed 'i' to '_'
            f.write(
                f"{str(packet['id_cluster']).zfill(id_length)}: {packet['aligned']}\n"
            )
        equals = self.print_align(cluster_packets["aligned"])
        f.write(f"{' '*(id_length+2)}{equals}\n")
        self.logger.debug(f"Finding fields for cluster {cluster_id}")
        fields = cluster_packets["fields"].iloc[0]
        f.write(
            f"{', '.join(map(lambda x: f'{int(x[0]/2)}-{int(x[1]/2)}{x[2]}', fields))}\n\n"
        )

    def print_align(
        self,
        packets: List[str],
    ) -> str:
        """Print alignment of packets.

        Args:
            packets (List[str]): List of aligned packets.

        Returns:
            str: String representing the alignment.
        """
        equals = ""
        for i in range(len(max(packets, key=len))):
            chars = [packet[i] for packet in packets if i < len(packet)]
            equal_count = sum(char == chars[0] for char in chars if char != "-")
            if all(char == chars[0] for char in chars) and chars[0] != "-":
                equals += "*"
            elif equal_count >= len(packets) * self.percent_equal:
                equals += "."
            else:
                equals += " "
        return equals

    def save_cluster_data_to_pcap(self):
        """Save data for each cluster to a pcap file."""
        for cluster_id in self.clusters:
            Pcap.write(
                self.df.loc[self.df["cluster"] == cluster_id, "original"],
                os.path.join(self.output_path, f"output.{cluster_id}.pcap"),
            )

    def execute(self):
        """Execute the entire process."""
        start_time = pd.Timestamp.now()
        self.prepare()
        self.run()
        self.post_run()
        end_time = pd.Timestamp.now()
        self.running_time = end_time - start_time
        self.cleanup()
        self.save()
