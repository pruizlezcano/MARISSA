import logging


class ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[94m",  # Blue
        "INFO": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",  # Red
        "CRITICAL": "\033[1;91m",  # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record):
        levelname = record.levelname
        message = super().format(record)
        return f"{self.COLORS.get(levelname, '')}{message}{self.RESET}"


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Logger(metaclass=Singleton):
    def __init__(self, verbose=False):
        self.logger = logging.getLogger("clustal")
        handler = logging.StreamHandler()
        formatter = ColoredFormatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)
