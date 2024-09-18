import os

from marissa.alignment_algorithm import AlignmentAlgorithm


class ClustaloAlgorithm(AlignmentAlgorithm):

    def __init__(self):
        super().__init__()

    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        os.system(
            f"clustalo --infile {input_file} --force --outfile {output_file} {'--verbose' if verbose else ''}"
        )
