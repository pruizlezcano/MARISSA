# MARISSA

MARISSA (MessAge foRmat Inference with Similarity digeSt Algorithms) is a tool for automatically inferring message formats from network traffic captures. By leveraging similarity digest algorithms and multiple sequence alignment techniques, MARISSA can identify and cluster similar packets, revealing underlying protocol patterns and message structures.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Installation

### Manual

#### Prequisites
* [Python](https://www.python.org/) 3.11
* [Poetry](https://python-poetry.org/) dependency manager
* One or more Multiple Sequence Alignment tools (check the paper for details):
  * [MAFFT](https://mafft.cbrc.jp/alignment/software/) ⭐
  * [Clustal Omega](http://www.clustal.org/omega/)
  * [MUSCLE](https://github.com/rcedgar/muscle)
  * [FAMSA](https://github.com/refresh-bio/FAMSA)

#### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/pruizlezcano/MARISSA.git
   ```

2. Install dependencies:
   ```bash
   poetry install
   ```

3. Install at least one Multiple Sequence Alignment tool (see Prerequisites)

### Docker

> [!NOTE]  
> This docker image only has MAFFT installed. If you want to use other alignment tools, you need to install them manually.

1. Clone the repository:
   ```bash
   git clone https://github.com/pruizlezcano/MARISSA.git
   ```
2. Build the Docker image:
   ```bash
   docker build -t marissa .
   ```
3. Run the Docker container:
   ```bash
   docker run -v "$(pwd):/data" marissa -i /data/input.pcap -o /data/results/input.pcap -v
   ```

 > [!IMPORTANT]
 > **Understanding the `-v "$(pwd):/data"` volume mount:**
 > This part of the command is crucial for letting MARISSA (running inside the Docker container) access your files and save results back to your computer.
 >
 > * `$(pwd)`: This is a shortcut that automatically uses the path to your current working directory on your computer (the folder you're in when you run the command).
 > * `/data`: This is the path *inside* the Docker container where your current directory will be made available.
 >
 > **What this means for you:**
 > * **Input files:** If you have `input.pcap` in your current directory, MARISSA can access it as `/data/input.pcap` from within the container.
 > * **Output files:** When MARISSA saves results to a path like `/data/results/input.pcap` inside the container, these files will actually appear in a `results/input.pcap` subfolder within your current directory on your computer.
 >
 > In simple terms, it makes using MARISSA with Docker much more straightforward.

## Usage

```bash
marissa -i input.pcap --remove-duplicates --remove-headers -v
```

### Options

* `--input`, `-i` `TEXT`: The .pcap file to read. This option is required.
* `--output`, `-o` `TEXT`: The output directory to write the results. Default: ./results/<pcap_name>/
* `--verbose`, `-v`: Prints the output of the commands run by the script.
* `--packet-length`, `-l` `INTEGER`: The length of the packets to filter. If not specified, all packets are considered.
* `--packet-length-variance`, `-p` `INTEGER`: The variance in the length of the packets to filter.
* `--percent-equal`, `-e` `FLOAT`: The percentage of equal packets to consider for representation. Accepts values between 0 and 1. Default is 1.
* `--remove-headers`: Remove headers from the packets.
* `--distance-algorithm`, `-d` [`tlsh`|`ssdeep`|`hamming`]: The distance algorithm to use for comparing packet similarity. Default is `ssdeep`.
* `--cluster-algorithm`, `-c` [`optics`|`kmeans`|`kmeans_hierarchical`]: The clustering algorithm to use. Default is `optics`.
* `--align-algorithm`, `-a` [`clustalo`|`maffttext`|`mafft`|`muscle`|`famsa`]: The alignment algorithm to use. Default is `mafft`.
* `--group_by_ethernet`, `-eth`: Group packets by their ethernet header and remove it before clustering.
* `--remove-duplicates`: Remove duplicate packets before clustering.
* `--slice-packet`, `-s` `INTEGER`: Remove the first x characters of the packet.
* `--ignore-noise`, `-n`: Ignore noise points (cluster -1) in the results.
* `--layer`, `-l` `INTEGER`: The layer to get the hex from the packet.
* `--help`: Show the help message and exit.

## Output Format

MARISSA generates the following output structure:

```
results/<pcap_name>/
├── output.<cluster>.pcap  # Packet capture files for each cluster
├── output.csv             # CSV file with the packet information
├── output.meta.json       # Metadata about the execution
└── output.txt             # Text file with a visual representation of aligned packets per cluster
```

The `output.csv` file contains the following columns:
* `cluster`: The cluster number.
* `cluster_id`: The packet ID in the cluster.
* `raw`: The raw packet data.
* `aligned`: The aligned packet data.
* `fields`: The fields of the packet.

The `output.meta.json` file contains metadata about the execution, including:
* `file`: The path to the input pcap file.
* `distance_algorithm`: The distance algorithm used.
* `cluster_algorithm`: The clustering algorithm used.
* `align_algorithm`: The alignment algorithm used.
* `merge_algorithm`: The algorithm used for merging fields.
* `clusters`: The number of clusters found.
* `packet_count`: The total number of packets processed.
* `remove_headers`: Indicates if headers were removed (null if not specified).
* `remove_duplicates`: Boolean indicating if duplicate packets were removed.
* `group_by_ethernet`: Boolean indicating if packets were grouped by Ethernet header.
* `slice_packet`: Indicates if packets were sliced (null if not specified).
* `ignore_noise`: Boolean indicating if noise points were ignored.
* `running_time`: The total execution time in seconds.
* `common_prefix`: The common prefix found across packets, if applicable.

## License

Licensed under the [GNU GPLv3](LICENSE) license.
