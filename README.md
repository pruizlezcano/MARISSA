# MARISSA

Marissa is a tool for protocol reverse engineerings and is part of my Bachelor's Thesis for the Telecommunications Engineering degree. It takes a previous network comunication as input and infer the messages by clustering and multiple sequence aligment.

## Installation

### Prequisites
* [Python](https://www.python.org/) 3.12
* [Poetry](https://python-poetry.org/) dependency manager

1. Clone the repository: `git clone https://github.com/pruizlezcano/MARISSA.git`
2. Install dependencies: `poetry install`
3. Download [Clustal Omega](http://www.clustal.org/omega/) and add it to your `PATH`

## Usage

1. Prepare a `.pcap` file with the network communication you wish to analyze.
2. Run Marissa with the necessary options. Here's an example command:

```bash
protocol-inference --input yourfile.pcap -v --packet-length 1500 --packet-length-variance 100 --percent-equal 0.8 --header-length 20 --distance-algorithm ssdeep --cluster-algorithm optics
```

### Options

* `--input`, `-i` `TEXT`: The .pcap file to read. This option is required.
* `--verbose`, `-v`: Prints the output of the commands run by the script.
* `--packet-length`, `-l` `INTEGER`: The length of the packets to filter. If not specified, all packets are considered.
* `--packet-length-variance`, `-p` `INTEGER`: The variance in the length of the packets to filter.
* `--percent-equal`, `-e` `FLOAT`: The percentage of equal packets to consider for writting the result file. Accepts values between 0 and 1. Default is 1.
* `--header-length`, `-h` `INTEGER`: The length of the packet headers. This is used to ignore the headers in the analysis.
* `--distance-algorithm`, `-d` [`tlsh`|`ssdeep`|`hamming`]: The distance algorithm to use for comparing packet similarity. Default is `ssdeep`.
* `--cluster-algorithm`, `-c` [`optics`|`kmeans`|`kmeans_hierarchical`]: The clustering algorithm to use. Default is `optics`.
* `--help`: Show the help message and exit.

## License

Licensed under the [GNU GPLv3](https://github.com/pruizlezcano/MARISSA/blob/main/LICENSE) license.