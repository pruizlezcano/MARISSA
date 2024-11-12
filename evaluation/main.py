import json
import logging
import os
import time
from datetime import timedelta

import pandas as pd

from evaluation import ResultsEvaluator
from marissa import (
    ClustaloAlgorithm,
    FamsaAlgorithm,
    MafftAlgorithm,
    MafftTextAlgorithm,
    Marissa,
    MergeByCalinskiHarabasz,
    MergeByDaviesBouldin,
    MergeByField,
    MergeBySilhouette,
    MuscleAlgorithm,
    OpticsAlgorithm,
    ProbconsAlgorithm,
    SSDEEPDistance,
)

# Configure logging
logging.basicConfig(
    filename="process.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger()


def run_marissa(
    input_file, alignment, cluster_merge, merge_threshold, output, ignore_noise=False
):
    marissa = Marissa(
        verbose=False,
        input_file=input_file,
        output=output,
        remove_headers=True,
        distance_algorithm=SSDEEPDistance,
        cluster_algorithm=OpticsAlgorithm,
        cluster_merger=cluster_merge,
        merge_threshold=merge_threshold,
        align_algorithm=alignment,
        group_by_ethernet=False,
        remove_duplicates=True,
        ignore_noise=ignore_noise,
    )
    marissa.execute()
    analyzer = ResultsEvaluator(f"{output}/output.csv")
    cluster_stats = analyzer.analyze_clusters()

    # Read number of clusters and running time from meta.json
    with open(f"{output}/output.meta.json", "r") as f:
        meta = json.load(f)
        cluster_stats["n_clusters"] = meta["clusters"]
        cluster_stats["running_time"] = meta["running_time"]

    return cluster_stats


def process_pcap(
    input_data,
    alignment_algorithms,
    cluster_merge_algorithms,
    merge_thresholds,
    total_runs,
):
    pcap_name = os.path.basename(input_data["pcap"])
    base_output_dir = f"./results/{pcap_name}"
    os.makedirs(base_output_dir, exist_ok=True)

    stats = []
    runs = 1
    start_time = time.time()
    avg_time_per_run = None

    for alignment in alignment_algorithms:
        for cluster_merge in cluster_merge_algorithms:
            thresholds = merge_thresholds if cluster_merge != MergeByField else [None]

            for merge_threshold in thresholds:
                for ignore_noise in [False, True]:
                    run_start = time.time()

                    # Calculate and format ETA
                    elapsed = str(timedelta(seconds=int(time.time() - start_time)))
                    if avg_time_per_run:
                        remaining_runs = total_runs - runs + 1
                        eta_seconds = avg_time_per_run * remaining_runs
                        eta = str(timedelta(seconds=int(eta_seconds)))
                    else:
                        eta = "calculating..."

                    logger.info(
                        f"[+] {runs}/{total_runs} (Elapsed: {elapsed} | ETA: {eta}) Running {pcap_name} "
                        f"{alignment.__qualname__} {cluster_merge.__qualname__} {merge_threshold} ignore_noise={ignore_noise}"
                    )

                    output_dir = os.path.join(
                        base_output_dir,
                        f"{alignment.__qualname__}_{cluster_merge.__qualname__}_{merge_threshold}_ignore_noise_{ignore_noise}",
                    )
                    os.makedirs(output_dir, exist_ok=True)

                    cluster_stats = run_marissa(
                        input_data["pcap"],
                        alignment,
                        cluster_merge,
                        merge_threshold,
                        output_dir,
                        ignore_noise=ignore_noise,
                    )

                    # Update average time per run
                    run_time = time.time() - run_start
                    if avg_time_per_run is None:
                        avg_time_per_run = run_time
                    else:
                        avg_time_per_run = (
                            avg_time_per_run * (runs - 1) + run_time
                        ) / runs

                    stats.append(
                        {
                            "pcap_name": pcap_name,
                            "alignment": alignment.__qualname__,
                            "cluster_merge": cluster_merge.__qualname__,
                            "merge_threshold": merge_threshold,
                            "ignore_noise": ignore_noise,
                            "cluster_stats": cluster_stats,
                        }
                    )
                    runs += 1

    # Create and save DataFrame for this PCAP
    df = pd.DataFrame(stats)
    df.set_index(
        ["pcap_name", "alignment", "cluster_merge", "merge_threshold", "ignore_noise"],
        inplace=True,
    )
    csv_path = os.path.join(base_output_dir, f"{pcap_name}_results.csv")
    df.to_csv(csv_path)

    return df


def main():
    inputs = [
        # {
        #     "pcap": "input/dhcp_100.pcap",
        #     "remove_headers": True,
        #     "group_by_ethernet": False,
        #     "remove_duplicates": True,
        # },
        {
            "pcap": "input/ftp.pcap",
            "remove_headers": True,
            "group_by_ethernet": False,
            "remove_duplicates": True,
        },
        # {
        #     "pcap": "input/ntp_1000.pcap",
        #     "remove_headers": True,
        #     "group_by_ethernet": True,
        #     "remove_duplicates": True,
        # },
        {
            "pcap": "input/dns.pcap",
            "remove_headers": True,
            "group_by_ethernet": True,
            "remove_duplicates": True,
        },
    ]
    alignment_algorithms = [
        MafftTextAlgorithm,
        MafftAlgorithm,
        ClustaloAlgorithm,
        FamsaAlgorithm,
        MuscleAlgorithm,
        ProbconsAlgorithm,
    ]
    cluster_merge_algorithms = [
        MergeByField,
        MergeBySilhouette,
        MergeByCalinskiHarabasz,
        MergeByDaviesBouldin,
    ]
    merge_thresholds = [x / 10.0 for x in range(1, 110, 1)]

    total_runs = (
        len(alignment_algorithms)
        * sum(
            len(merge_thresholds) if cm != MergeByField else 1
            for cm in cluster_merge_algorithms
        )
        * 2  # ignore_noise=True and False
    )

    # Process each PCAP independently
    all_results = []
    for input_data in inputs:
        df = process_pcap(
            input_data,
            alignment_algorithms,
            cluster_merge_algorithms,
            merge_thresholds,
            total_runs,
        )
        all_results.append(df)


if __name__ == "__main__":
    main()
