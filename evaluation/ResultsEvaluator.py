import json
import os
import shutil

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from matplotlib.patches import Patch
from rich.console import Console
from scapy.all import *
from sklearn.manifold import TSNE
from sklearn.metrics import adjusted_rand_score

from marissa import (
    DistanceAlgorithm,
    HammingDistance,
    Pcap,
    SSDEEPDistance,
    TLSHDistance,
)

console = Console()


class ResultsEvaluator:
    def __init__(self, results_file_input: str) -> None:
        self.client_message_types = set()
        self.server_message_types = set()
        self.df = pd.read_csv(results_file_input)
        with open(results_file_input.replace(".csv", ".meta.json")) as f:
            self.meta = json.load(f)

    @staticmethod
    def run_tshark(pcap_path: str) -> dict:
        output_path = pcap_path.replace(".pcap", ".json")
        os.system(f"tshark -r {pcap_path} -T json > {output_path}")
        with open(output_path) as f:
            return json.load(f)

    def get_packet_type(self, packet: dict) -> str:
        layers = packet["_source"]["layers"]
        if "dns" in layers:
            res = "DNS-"
            flags = layers["dns"]["dns.flags"]
            if int(flags, 0) & 0x8000:
                self.server_message_types.add(flags)
            else:
                self.client_message_types.add(flags)
            message_type = res + str(flags)
            return message_type
        elif "ftp" in layers:
            res = "FTP"
            res += "-Q-" if layers["ftp"]["ftp.request"] == "1" else "-R-"
            ftp_command = list(layers["ftp"].keys())[2]
            if "ftp.request.command" in layers["ftp"][ftp_command]:
                self.client_message_types.add(
                    layers["ftp"][ftp_command]["ftp.request.command"]
                )
                res += layers["ftp"][ftp_command]["ftp.request.command"]
            elif "ftp.response.code" in layers["ftp"][ftp_command]:
                self.server_message_types.add(
                    layers["ftp"][ftp_command]["ftp.response.code"]
                )
                res += layers["ftp"][ftp_command]["ftp.response.code"]
            else:
                if "-Q-" in res:
                    self.client_message_types.add("UNKNOWN")
                else:
                    self.server_message_types.add("UNKNOWN")
                res += "UNKNOWN"
            return res
        return "UNKNOWN"

    def analyze(self) -> None:
        os.makedirs("temp", exist_ok=True)

        console.print("[+] Checking intra-cluster message types", style="bold blue")
        for cluster in self.df["cluster"].unique():
            cluster_packets = self.df[self.df["cluster"] == cluster]["raw"].tolist()

            pcap_path = f"temp/{cluster}.pcap"
            Pcap.write(cluster_packets, pcap_path)

            cluster_packets = self.run_tshark(pcap_path)

            for i, packet in enumerate(cluster_packets):
                message_type = self.get_packet_type(packet)
                self.df.loc[
                    (self.df["cluster"] == cluster) & (self.df["id_cluster"] == i),
                    "message_type",
                ] = message_type

            message_types = self.df[self.df["cluster"] == cluster][
                "message_type"
            ].unique()

            if len(message_types) > 1:
                console.print(
                    f"Cluster {cluster} has {len(message_types)} different types of messages: {message_types}",
                    style="bold red",
                )
            else:
                console.print(
                    f"Cluster {cluster} OK",
                    style="bold green",
                )

        console.print("[+] Checking inter-cluster message types", style="bold blue")
        cluster_ids = self.df["cluster"].unique()
        all_different = True

        for i, cluster_id in enumerate(cluster_ids):
            for j in range(i + 1, len(cluster_ids)):
                other_cluster_id = cluster_ids[j]
                if set(
                    self.df[self.df["cluster"] == cluster_id]["message_type"]
                ) == set(
                    self.df[self.df["cluster"] == other_cluster_id]["message_type"]
                ):
                    all_different = False
                    console.print(
                        f"Cluster {cluster_id} and Cluster {other_cluster_id} have the same message types: {set(self.df[self.df['cluster'] == cluster_id]['message_type'])}",
                        style="bold yellow",
                    )

        if all_different:
            console.print(
                "All clusters have different message types", style="bold green"
            )

        console.print("[+] Message types", style="bold blue")
        console.print(
            f"Client message types: {len(self.client_message_types)} {self.client_message_types}"
        )
        console.print(
            f"Server message types: {len(self.server_message_types)} {self.server_message_types}"
        )

        console.print("[+] Adjusted Rand Index", style="bold blue")
        # get true labels from message types
        type_to_labels = {}
        message_types = self.df["message_type"].unique()
        for message_type in message_types:
            if message_type not in type_to_labels:
                type_to_labels[message_type] = len(type_to_labels)
        true_labels = self.df["message_type"].map(type_to_labels)

        predicted_labels = self.df["cluster"].unique()
        predicted_labels = pd.Series(
            [list(predicted_labels).index(i) for i in self.df["cluster"]]
        )

        asi = adjusted_rand_score(predicted_labels, true_labels)
        console.print(f"Adjusted Rand Index: {asi}", style="bold green")

        shutil.rmtree("temp")

    def plot_clusters(self, save_path: str = None):
        distance_algorithm: DistanceAlgorithm
        if self.meta["distance_algorithm"] == "HammingDistance":
            distance_algorithm = HammingDistance()
        elif self.meta["distance_algorithm"] == "SSDEEPDistance":
            distance_algorithm = SSDEEPDistance()
        elif self.meta["distance_algorithm"] == "TLSHDistance":
            distance_algorithm = TLSHDistance()
        else:
            raise ValueError("Invalid distance algorithm")
        data = list(map(lambda x: x.replace("-", ""), self.df["raw"].tolist()))
        nodes = [distance_algorithm.calculate_node(i) for i in data]
        distances = np.zeros((len(nodes), len(nodes)))
        for i in range(len(nodes)):
            for j in range(len(nodes)):
                distances[i, j] = distance_algorithm.compare(nodes[i], nodes[j])

        # plot
        tsne = TSNE(n_components=2, random_state=0)
        points = tsne.fit_transform(distances)
        # Set figure size to be large, which should fill most screens.
        fig, ax = plt.subplots(figsize=(16, 9))
        # Convert clusters to unique integers
        unique_clusters = list(set(self.df["cluster"]))
        cluster_colors = [
            unique_clusters.index(cluster) for cluster in self.df["cluster"]
        ]
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
        legend_elements = [
            Patch(facecolor=plt.cm.viridis(norm(i)), label=cluster)
            for i, cluster in enumerate(unique_clusters)
        ]
        fig.legend(
            handles=legend_elements,
            title="Clusters",
            loc="outside upper right",
        )
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()

    def plot_alignment(self, save_path: str = None):
        num_equals = {}
        max_length = 0

        for cluster in self.df["cluster"].unique():
            cluster_df = self.df[self.df["cluster"] == cluster]
            length = len(cluster_df["aligned"].iloc[0])
            max_length = max(max_length, length)
            num_equals[cluster] = np.zeros(length)
            for i in range(length):
                char_count = {}
                for j in range(1, len(cluster_df["aligned"])):
                    char = cluster_df["aligned"].iloc[j][i]
                    if char == "-":
                        continue
                    if not char in char_count:
                        char_count[char] = 0
                    char_count[char] += 1

                num_equals[cluster][i] = max(char_count.values())

        # subplot for each cluster
        num_clusters = len(num_equals)
        fig, axes = plt.subplots(num_clusters, 1, figsize=(10, 5 * num_clusters))

        if num_clusters == 1:
            axes = [axes]

        for ax, (cluster, values) in zip(axes, num_equals.items()):
            ax.bar(range(len(values)), values, label=f"Cluster {cluster}")
            ax.set_xlabel("Position")
            ax.set_ylabel("Frequency")
            ax.set_title(f"Alignment for Cluster {cluster}")

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()

    def plot(self):
        print(self.meta)
        self.plot_clusters()
        self.plot_alignment()
