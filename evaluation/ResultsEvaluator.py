import json
import os

import pandas as pd
from rich.console import Console
from scapy.all import *
from sklearn.metrics import (
    accuracy_score,
    adjusted_mutual_info_score,
    adjusted_rand_score,
    completeness_score,
    f1_score,
    homogeneity_score,
    precision_score,
    recall_score,
    v_measure_score,
)

from evaluation.utils import run_tshark
from marissa import Pcap

console = Console()


class ResultsEvaluator:
    def __init__(self, results_file_input: str) -> None:
        self.client_message_types = set()
        self.server_message_types = set()
        self.df = pd.read_csv(results_file_input)
        with open(results_file_input.replace(".csv", ".meta.json")) as f:
            self.meta = json.load(f)

    def remove_tshark_headers(self, packet: dict) -> dict:
        packet["_source"]["layers"].pop("frame")
        packet["_source"]["layers"].pop("eth")
        packet["_source"]["layers"].pop("ip")
        if "udp" in packet["_source"]["layers"]:
            packet["_source"]["layers"].pop("udp")
        if "tcp" in packet["_source"]["layers"]:
            packet["_source"]["layers"].pop("tcp")
        if "vlan" in packet["_source"]["layers"]:
            packet["_source"]["layers"].pop("vlan")
        return packet

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
        elif "ntp" in layers:
            res = "NTP"
            if layers["ntp"]["ntp.flags_tree"]["ntp.flags.mode"] == "3":
                self.client_message_types.add(layers["ntp"]["ntp.flags"])
                res += "-Q-"
            elif layers["ntp"]["ntp.flags_tree"]["ntp.flags.mode"] == "4":
                self.server_message_types.add(layers["ntp"]["ntp.flags"])
                res += "-R-"
            else:
                res += "-UNKNOWN-"
            res += layers["ntp"]["ntp.flags"]
            return res
        elif "icmp" in layers:
            res = "ICMP"
            if layers["icmp"]["icmp.type"] == "8":
                self.client_message_types.add(layers["icmp"]["icmp.type"])
                res += "-Q-"
            elif layers["icmp"]["icmp.type"] == "0":
                self.server_message_types.add(layers["icmp"]["icmp.type"])
                res += "-R-"
            else:
                res += "-UNKNOWN-"
            res += layers["icmp"]["icmp.type"]
            return res
        elif "dhcp" in layers:
            res = "DHCP"
            if layers["dhcp"]["dhcp.type"] == "1":
                self.client_message_types.add(layers["dhcp"]["dhcp.type"])
                res += "-Q-"
            elif layers["dhcp"]["dhcp.type"] == "2":
                self.server_message_types.add(layers["dhcp"]["dhcp.type"])
                res += "-R-"
            else:
                res += "-UNKNOWN-"
            res += layers["dhcp"]["dhcp.type"]
            return res
        return "UNKNOWN"

    def get_packet_fields(self, packet: dict) -> List[str]:
        res = []
        ignore_keys = [
            "dns.qry.name.len_raw",
            "dns.count.labels_raw",
            "icmp.ident_le_raw",
            "icmp.seq_le_raw",
            "ftp.request.arg_raw",
            "ip.hdr_len_raw",
        ]
        for key, value in packet.items():
            if "payload" in key or "tree" in key or key in ignore_keys:
                continue
            if isinstance(value, dict):
                res += self.get_packet_fields(value)
            elif "raw" in key and "." in key:
                res += [value[0]]
        return res

    def get_true_fields(self, packets: List[dir]) -> List[str]:
        fields = []
        true_fields = []
        for packet in packets:
            fields.append(self.get_packet_fields(packet))

        # all indices should have the same length
        max_len = max(map(len, fields))
        for field in fields:
            if len(field) < max_len:
                field += [""] * (max_len - len(field))

        if "ftp" in packets[0]["_source"]["layers"]:
            temp = []
            for i in range(len(fields)):
                temp = fields[i]
                if len(temp) > 1:
                    temp.insert(1, "20")
                temp.append("0da0")
                fields[i] = temp

        fields = list(map(list, zip(*fields)))  # transpose
        offset = 0
        for field in fields:
            max_len = max(map(len, field))
            type = "D"
            if len(set(field)) == 1:  # all elements are the same
                type = "S"
            elif len(set(map(len, field))) > 1:  # different lengths
                type = "V"
            true_fields.append([offset, max_len, type])
            offset += max_len

        return true_fields

    def analyze(self):
        self.analyze_clusters()
        self.analyze_fields()

    def analyze_clusters(self) -> dict:
        os.makedirs("temp", exist_ok=True)

        console.print(self.meta)

        console.print("[+] Checking intra-cluster message types", style="bold blue")
        for cluster in self.df["cluster"].unique():
            cluster_packets = self.df[self.df["cluster"] == cluster]["raw"].tolist()

            pcap_path = f"temp/{cluster}.pcap"
            Pcap.write(cluster_packets, pcap_path)

            cluster_packets = run_tshark(pcap_path)

            if self.meta["remove_headers"]:
                cluster_packets = list(map(self.remove_tshark_headers, cluster_packets))

            self.df.loc[self.df["cluster"] == cluster, "tshark"] = cluster_packets

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
                    f"Cluster {cluster} OK: {message_types}",
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

        console.print("[+] Cluster Metrics", style="bold blue")
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

        stats = {
            "precision": precision_score(
                true_labels, predicted_labels, average="weighted"
            ),
            "accuracy": accuracy_score(true_labels, predicted_labels),
            "recall": recall_score(true_labels, predicted_labels, average="weighted"),
            "f1": f1_score(true_labels, predicted_labels, average="weighted"),
            "homogeneity": homogeneity_score(true_labels, predicted_labels),
            "completeness": completeness_score(true_labels, predicted_labels),
            "v_measure": v_measure_score(true_labels, predicted_labels),
            "adjusted_rand": adjusted_rand_score(predicted_labels, true_labels),
            "adjusted_mutual_info": adjusted_mutual_info_score(
                predicted_labels, true_labels
            ),
        }
        console.print(stats)
        return stats

    def analyze_fields(self) -> dict:
        console.print("[+] Checking fields", style="bold blue")
        stats = {}
        for cluster in self.df["cluster"].unique():
            print("====================")
            console.print(f"Cluster {cluster}")
            cluster_packets = self.df[self.df["cluster"] == cluster]["tshark"].tolist()
            true_fields = self.get_true_fields(cluster_packets)
            inferred_fileds = self.df[self.df["cluster"] == cluster]["fields"].tolist()[
                0
            ]
            inferred_fileds = eval(inferred_fileds)
            plain_inferred_fields = ""
            for field in inferred_fileds:
                plain_inferred_fields += field[2] * field[1]
            plain_true_fields = ""
            for field in true_fields:
                plain_true_fields += field[2] * field[1]

            print("====================")
            print("-", plain_inferred_fields)
            print("+", plain_true_fields)

            # same length
            if len(plain_inferred_fields) < len(plain_true_fields):
                plain_inferred_fields += "0" * (
                    len(plain_true_fields) - len(plain_inferred_fields)
                )
            else:
                plain_true_fields += "0" * (
                    len(plain_inferred_fields) - len(plain_true_fields)
                )

            cluster_stats = {
                "precision": precision_score(
                    list(plain_true_fields),
                    list(plain_inferred_fields),
                    average="micro",
                ),
                "accuracy": accuracy_score(
                    list(plain_true_fields), list(plain_inferred_fields)
                ),
                "recall": recall_score(
                    list(plain_true_fields),
                    list(plain_inferred_fields),
                    average="micro",
                ),
                "f1": f1_score(
                    list(plain_true_fields),
                    list(plain_inferred_fields),
                    average="micro",
                ),
                "homogeneity": homogeneity_score(
                    list(plain_true_fields), list(plain_inferred_fields)
                ),
                "completeness": completeness_score(
                    list(plain_true_fields), list(plain_inferred_fields)
                ),
                "v_measure": v_measure_score(
                    list(plain_true_fields), list(plain_inferred_fields)
                ),
                "adjusted_rand": adjusted_rand_score(
                    list(plain_true_fields), list(plain_inferred_fields)
                ),
            }
            stats[cluster] = cluster_stats
            console.print(cluster_stats)
            print("====================")
        return stats
