import os

from marissa.alignment_algorithm import AlignmentAlgorithm


class ProbconsAlgorithm(AlignmentAlgorithm):

    def __init__(self):
        super().__init__()

    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        os.system(f"probcons {'-v' if verbose else ''} {input_file} > {output_file}")
