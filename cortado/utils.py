import logging


def configure_logging(logging_level: int = logging.DEBUG):
    logging.getLogger("cortado").setLevel(logging_level)
