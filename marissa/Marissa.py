import os

import pandas as pd

from marissa.alignment_algorithm import AlignmentAlgorithm
from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.distance_metrics import DistanceAlgorithm
from marissa.Logger import Logger
from marissa.pcap import Pcap
from marissa.utils import remove_files


class Marissa:
    """Main class for the Marissa tool."""

    def __init__(
        self,
        verbose=False,
        packet_length: int = None,
        packet_length_variance: int = None,
        percent_equal: int = 1,
        input_file=None,
        output_file=None,
        remove_headers: bool = False,
        distance_algorithm: DistanceAlgorithm = None,
        cluster_algorithm: ClusterAlgorithm = None,
        align_algorithm: AlignmentAlgorithm = None,
        group_by_ethernet: bool = False,
        remove_duplicates: bool = False,
    ):
        self.input_file = input_file
        self.output_file = output_file
        self.output_path = os.path.dirname(output_file)
        self.max_length: int
        self.verbose = verbose
        self.packet_length = packet_length
        self.packet_length_variance = packet_length_variance
        self.percent_equal = percent_equal
        self.remove_headers = remove_headers
        self.clusters: int
        self.logger = Logger(verbose)
        self.pcap = Pcap(input_file)
        self.distance_algorithm: DistanceAlgorithm = distance_algorithm()
        self.cluster_algorithm: ClusterAlgorithm = cluster_algorithm
        self.align_algorithm: AlignmentAlgorithm = align_algorithm()
        self.group_by_ethernet = group_by_ethernet
        self.remove_duplicates = remove_duplicates

    def prepare(self):
        """Prepare the data for the clustal test."""
        self.load_data()
        if self.packet_length is not None:
            self.filter_data_by_packet_length()
        if self.remove_headers:
            self.remove_header()
        if self.remove_duplicates:
            self.remove_duplicate_packets()
        self.df = self.df.dropna()
        self.df = self.df.head(1000)
        self.max_length = max(self.df["length"])
        self.clusterize()
        self.encode_data()

    def load_data(self):
        """Load data from input file and calculate necessary features."""
        self.logger.debug("Loading data from input file")
        packets = self.pcap.load()
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
        """Clusterize the data using KMeans"""
        self.logger.debug("Performing clustering...")
        if self.group_by_ethernet:
            # get groups of packets with the same ethernet header
            self.df["group"] = self.df.groupby("ethernet").ngroup()

            for group_id, group_packets in self.df.groupby("group"):
                nodes = [
                    self.distance_algorithm.calculate_node(packet)
                    for packet in group_packets["hex"]
                ]
                clusterizer = self.cluster_algorithm(nodes, self.distance_algorithm)
                self.df.loc[self.df["group"] == group_id, "cluster"] = list(
                    map(lambda x: f"{group_id}s{x}", clusterizer.perform_clustering())
                )
        else:
            nodes = [
                self.distance_algorithm.calculate_node(packet)
                for packet in self.df["hex"]
            ]
            clusterizer = self.cluster_algorithm(nodes, self.distance_algorithm)
            self.df["cluster"] = clusterizer.perform_clustering()
        self.clusters = self.df["cluster"].unique()
        self.logger.info(f"Clustering done. Found {len(self.clusters)} clusters")
        self.df["id_cluster"] = self.df.groupby("cluster").cumcount()
        # clusterizer.plot(self.df["cluster"])

    def encode_data(self):
        """Encode the data and save it to a file."""
        for cluster_id, cluster_packets in self.df.groupby("cluster"):
            self.align_algorithm.encode(
                cluster_packets["hex"],
                os.path.join(self.output_path, f"input.{cluster_id}.fasta"),
            )

    def run(self):
        """Run the alignment algorithm."""
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

    def decode_aligned_data(self):
        """Decode aligned data for each cluster."""
        self.logger.info("Decoding aligned data")
        for cluster_id in self.clusters:

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
        self.save_results_to_file()
        self.save_cluster_data_to_pcap()

    def save_results_to_file(self):
        """Save results to a file."""
        self.logger.info("Saving results to file")
        with open(self.output_file, "w") as f:
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
        """Write data for a specific cluster to a file."""
        f.write(f"CLUSTER {cluster_id}:\n")
        id_length = max(len(str(x)) for x in cluster_packets["id_cluster"])
        for i, packet in cluster_packets.iterrows():
            f.write(
                f"{str(packet['id_cluster']).zfill(id_length)}: {packet['aligned']}\n"
            )
        equals = self.print_align(cluster_packets["aligned"])
        f.write(f"{' '*(id_length+2)}{equals}\n")
        self.logger.debug(f"Finding fields for cluster {cluster_id}")
        fields = self.find_fields(cluster_packets["aligned"])
        f.write(f"{", ".join(map(lambda x: f"{int(x[0]/2)}{x[1]}", fields))}\n\n")

    @staticmethod
    def _has_even_bytes(fields) -> bool:
        for i in fields:
            if len(i) % 2 != 0:
                return False
        return True

    @staticmethod
    def _is_variable_field(fields) -> bool:
        for i in fields:
            if "-" in i:
                return True
        return False

    def find_fields(self, packets: list[str]) -> list:
        """Find fields in the packets.

        Args:
            packets (list[str]): List of packets

        Returns:
            list: List of fields
        """
        message_length = len(max(packets, key=len))
        results_fields = []
        i = 0
        isLastStatic = False
        while i < message_length:
            offset = 2
            while i + offset <= message_length:
                field = [packet[i : i + offset] for packet in packets]
                if not self._has_even_bytes(field):
                    offset += 1
                    continue
                else:
                    break
            if not len(set(field)) == 1:
                if self._is_variable_field(field):
                    fields_info = [offset, "V"]
                else:
                    fields_info = [offset, "D"]
                results_fields.append(fields_info)
                isLastStatic = False
            else:
                if isLastStatic:
                    results_fields[-1][0] += offset
                else:
                    fields_info = [offset, "S"]
                    results_fields.append(fields_info)
                isLastStatic = True

            i += offset

        return results_fields

    def print_align(
        self,
        packets: list[str],
    ) -> str:
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
            self.pcap.write(
                self.df.loc[self.df["cluster"] == cluster_id, "original"],
                os.path.join(self.output_path, f"output.{cluster_id}.pcap"),
            )

    def execute(self):
        """Execute the entire process."""
        self.prepare()
        self.run()
        self.post_run()
        self.cleanup()
        self.save()
