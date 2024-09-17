import os
from abc import ABC, abstractmethod

from marissa.Logger import Logger


class AlignmentAlgorithm(ABC):
    def __init__(self):
        self.logger = Logger()

    @abstractmethod
    def encode(self, data: list[str], output_file: str):
        """Encode the data to a file.

        Args:
            data (list[str]): Data to encode.
            output_file (str): File to write the encoded data to.
        """
        pass

    @abstractmethod
    def decode(self, input_file: str) -> list[int]:
        """Decode the data from a file.

        Args:
            input_file (str): File to read the encoded data from.

        Returns:
            list[int]: Decoded data.
        """
        pass

    @abstractmethod
    def run(self, verbose: bool, input_file: str, output_file: str) -> None:
        """Run the alignment algorithm."""
        pass

    def read_file(self, filename: str) -> list[str]:
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                return f.read().splitlines()
        else:
            self.logger.error(f"{filename}\t: Not a file")
