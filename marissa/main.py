import os
from enum import Enum

import typer

from marissa import (
    ClustaloAlgorithm,
    HammingDistance,
    KMeansAlgorithm,
    KMeansHierarchicalAlgorithm,
    MafftAlgorithm,
    Marissa,
    MuscleAlgorithm,
    OpticsAlgorithm,
    SSDEEPDistance,
    TLSHDistance,
)

app = typer.Typer(
    name="main",
    help="MessAge foRmat Inference with Similarity digeSt Algorithms",
    invoke_without_command=True,
    add_completion=False,
)


class Distance_Types(str, Enum):
    tlsh = "tlsh"
    ssdeep = "ssdeep"
    hamming = "hamming"


class Cluster_Types(str, Enum):
    optics = "optics"
    kmeans = "kmeans"
    kmeans_hierarchical = "kmeans_hierarchical"


class Align_Types(str, Enum):
    clustalo = "clustalo"
    mafft = "mafft"
    muscle = "muscle"


@app.callback()
def main(
    pcap: str = typer.Option(
        ...,  # Required
        "--input",
        "-i",
        help="The pcap file to read",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        is_eager=True,
        help="Prints the output of the commands ran by the script.",
    ),
    packet_length: int = typer.Option(
        None,
        "--packet-length",
        "-l",
        help="The length of the packets to filter.",
    ),
    packet_length_variance: int = typer.Option(
        None,
        "--packet-length-variance",
        "-p",
        help="The variance of the length of the packets to filter.",
    ),
    percent_equal: float = typer.Option(
        1,
        "--percent-equal",
        "-e",
        help="The percentage of equal packets to consider. [0-1]",
    ),
    header_length: int = typer.Option(
        None,
        "--header-length",
        "-h",
        help="The length of the header of the packets.",
    ),
    distance_type: Distance_Types = typer.Option(
        Distance_Types.ssdeep,
        "--distance-algorithm",
        "-d",
        help="The distance algorithm to use.",
        case_sensitive=False,
    ),
    cluster_type: Cluster_Types = typer.Option(
        Cluster_Types.optics,
        "--cluster-algorithm",
        "-c",
        help="The cluster algorithm to use.",
        case_sensitive=False,
    ),
    align_type: Align_Types = typer.Option(
        Align_Types.mafft,
        "--align-algorithm",
        "-a",
        help="The align algorithm to use.",
        case_sensitive=False,
    ),
    group_by_ethernet: bool = typer.Option(
        False,
        "--group_by_ethernet",
        "-eth",
        help="Group packets by it's ethernet header and remove it before clustering.",
    ),
    remove_duplicates: bool = typer.Option(
        False,
        "--remove-duplicates",
        help="Remove duplicate packets before clustering.",
    ),
):
    distance_type = {
        Distance_Types.tlsh: TLSHDistance,
        Distance_Types.ssdeep: SSDEEPDistance,
        Distance_Types.hamming: HammingDistance,
    }[distance_type]
    cluster_type = {
        Cluster_Types.optics: OpticsAlgorithm,
        Cluster_Types.kmeans: KMeansAlgorithm,
        Cluster_Types.kmeans_hierarchical: KMeansHierarchicalAlgorithm,
    }[cluster_type]
    align_type = {
        Align_Types.mafft: MafftAlgorithm,
        Align_Types.clustalo: ClustaloAlgorithm,
        Align_Types.muscle: MuscleAlgorithm,
    }[align_type]
    pcap_name = os.path.basename(pcap)
    results_path = f"./results/{pcap_name}"
    os.makedirs(results_path, exist_ok=True)

    marissa_runner = Marissa(
        verbose=verbose,
        input_file=pcap,
        output_file=os.path.join(results_path, "output.txt"),
        packet_length=packet_length,
        packet_length_variance=packet_length_variance,
        percent_equal=percent_equal,
        header_length=header_length,
        distance_algorithm=distance_type,
        cluster_algorithm=cluster_type,
        align_algorithm=align_type,
        group_by_ethernet=group_by_ethernet,
        remove_duplicates=remove_duplicates,
    )
    marissa_runner.execute()


if __name__ == "__main__":
    app()
