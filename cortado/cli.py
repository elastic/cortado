import logging

import structlog
import typer
import json

from pathlib import Path

from rich import box
from rich.table import Table
from rich.console import Console
from rich.text import Text

from cortado import mapping
from cortado.rtas import get_registry, load_all_modules
from cortado.utils import configure_logging

from typing import Any

app = typer.Typer()

log = structlog.get_logger(__name__)


@app.command()
def print_rtas(as_json: bool = False):
    """
    Print information about all available RTAs
    """
    load_all_modules()

    registry = get_registry()
    sorted_names = sorted(registry.keys())

    if as_json:
        rtas_data: list[dict[str, Any]] = [registry[name].as_dict() for name in sorted_names]
        print(json.dumps(rtas_data, sort_keys=True))
        return

    table = Table(show_header=True, header_style="bold magenta", show_lines=True, box=box.ROUNDED)
    table.add_column("ID", no_wrap=True)
    table.add_column("Name")
    table.add_column("Platforms")
    table.add_column("Endpoint Rules")
    table.add_column("SIEM Rules")
    table.add_column("Techniques")

    for name in sorted_names:
        rta = registry[name]
        table.add_row(
            Text.assemble((rta.id, "dim")),
            rta.name,
            ", ".join(rta.platforms),
            str(len(rta.endpoint_rules)),
            str(len(rta.siem_rules)),
            ", ".join(rta.techniques),
        )
    console = Console()
    console.print(table)


@app.command()
def generate_mapping(mapping_file: Path = mapping.DEFAULT_MAPPING_FILE):
    """
    Generate a mapping file that contains rule to RTA relations.
    """
    log.info("Generating rule-to-RTA mapping file", path=str(mapping_file))

    data = mapping.generate_mapping()
    with open(mapping_file, 'w') as f:
        json.dump(data, f, sort_keys=True, indent=4)

    log.info("Mapping file saved", path=str(mapping_file))


@app.callback()
def main(verbose: bool = False, logs_as_json: bool = False):
    logging_level = logging.DEBUG if verbose else logging.INFO
    configure_logging(logging_level, as_json=logs_as_json)


def run_cli():
    app()
