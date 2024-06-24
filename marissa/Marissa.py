import os

import pandas as pd

from marissa.cluster_algorithm import ClusterAlgorithm
from marissa.distance_metrics import DistanceAlgorithm
from marissa.dna.decoder import main as dna_decoder
from marissa.dna.encoder import main as dna_encoder
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
        header_length: int = None,
        distance_algorithm: DistanceAlgorithm = None,
        cluster_algorithm: ClusterAlgorithm = None,
    ):
        self.input_file = input_file
        self.output_file = output_file
        self.output_path = os.path.dirname(output_file)
        self.max_length: int
        self.verbose = verbose
        self.packet_length = packet_length
        self.packet_length_variance = packet_length_variance
        self.percent_equal = percent_equal
        self.header_length = header_length
        self.clusters: int
        self.logger = Logger(verbose)
        self.pcap = Pcap(input_file)
        self.distance_algorithm: DistanceAlgorithm = distance_algorithm()
        self.cluster_algorithm: ClusterAlgorithm = cluster_algorithm

    def prepare(self):
        """Prepare the data for the clustal test."""
        self.load_data()
        if self.packet_length is not None:
            self.filter_data_by_packet_length()
        self.df = self.df.head(1000)
        self.max_length = max(self.df["length"])
        if self.header_length is not None:
            self.remove_header()
        self.clusterize()
        self.encode_data()

    def load_data(self):
        """Load data from input file and calculate necessary features."""
        self.logger.debug("Loading data from input file")
        packets = self.pcap.load()
        self.logger.info(f"Loaded {len(packets)} packets")
        self.df = pd.DataFrame([i.hex for i in packets], columns=["raw"])
        self.df["original"] = self.df["raw"]
        self.df["length"] = self.df["raw"].apply(lambda x: len(x) // 2)
        self.df["id"] = self.df.index + 1

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
        if self.header_length is not None:
            self.logger.debug("Removing header from data")
            self.df["raw"] = [x[self.header_length :] for x in self.df["raw"]]

    def clusterize(self):
        """Clusterize the data using KMeans"""

        nodes = [
            self.distance_algorithm.calculate_node(packet) for packet in self.df["raw"]
        ]
        clusterizer = self.cluster_algorithm(nodes, self.distance_algorithm)

        self.logger.debug("Performing clustering...")
        self.df["cluster"] = clusterizer.perform_clustering()
        self.clusters = self.df["cluster"].unique()
        self.logger.info(f"Clustering done. Found {len(self.clusters)} clusters")
        self.df["id_cluster"] = self.df.groupby("cluster").cumcount()
        # clusterizer.plot(self.df["cluster"])

    def encode_data(self):
        """Encode the data and save it to a file."""
        for cluster_id, cluster_packets in self.df.groupby("cluster"):
            dna_encoder(
                cluster_packets["raw"],
                os.path.join(self.output_path, f"input.{cluster_id}.fasta"),
            )

    def run(self):
        """Run clustal omega"""
        for cluster_id in self.clusters:
            self.run_clustal_omega_for_cluster(cluster_id)

    def run_clustal_omega_for_cluster(self, cluster_id):
        """Run clustal omega for a specific cluster."""
        self.logger.info(f"Running clustal omega for cluster {cluster_id}")
        os.system(
            f"clustalo --infile {os.path.join(self.output_path,f"input.{cluster_id}.fasta")} --force --wrap={self.max_length*1000} --outfmt clustal --outfile {os.path.join(self.output_path,f"output.{cluster_id}.clustal_num")} {'--verbose' if self.verbose else ''}"  # noqa E501
        )

    def post_run(self):
        """Post run actions"""
        self.decode_aligned_data()

    def decode_aligned_data(self):
        """Decode aligned data for each cluster."""
        self.logger.debug("Decoding aligned data")
        for cluster_id in self.clusters:

            data_aligned = dna_decoder(
                os.path.join(self.output_path, f"output.{cluster_id}.clustal_num")
            )
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
            f.write(f"Cluster Algorithm: {self.cluster_algorithm.__qualname__}\n")
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
        f.write(
            f"{' '*(id_length+2)}{self.print_align(cluster_packets['aligned'])}\n\n"
        )

    def print_align(
        self,
        packets: list[str],
    ):
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
