import logging

import structlog
import typer

from cortado.rtas import get_registry, load_all_modules
from cortado.utils import configure_logging

app = typer.Typer()

log = structlog.get_logger(__name__)


@app.command()
def print_rtas():
    log.info("Printing out all RTAs found")
    load_all_modules()

    registry = get_registry()
    sorted_names = sorted(registry.keys())

    for name in sorted_names:
        print(name)


@app.callback()
def main(verbose: bool = False, logs_as_json: bool = False):
    logging_level = logging.DEBUG if verbose else logging.INFO
    configure_logging(logging_level, as_json=logs_as_json)


def run_cli():
    app()
