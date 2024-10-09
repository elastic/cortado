import logging

import structlog
import typer
import json

from pathlib import Path
from collections import Counter

from rich import box
from rich.table import Table
from rich.console import Console
from rich.text import Text

from cortado import mapping, rules
from cortado.rtas import get_registry
from cortado.utils import configure_logging

from typing import Any

app = typer.Typer()

log = structlog.get_logger(__name__)


@app.command()
def print_rtas(as_json: bool = False):
    """
    Print information about all available RTAs
    """
    registry = get_registry()
    sorted_names = sorted(registry.keys())

    if as_json:
        rtas_data: list[dict[str, Any]] = [registry[name].as_dict() for name in sorted_names]
        print(json.dumps(rtas_data, sort_keys=True))
        return

    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL, border_style="grey50")
    table.add_column("ID", no_wrap=True)
    table.add_column("Name")
    table.add_column("Platforms")
    table.add_column("Endpoint Rules")
    table.add_column("SIEM Rules")
    table.add_column("Techniques")

    for name in sorted_names:
        rta = registry[name]

        if not rta.endpoint_rules and not rta.siem_rules:
            endpoint_rules_count = Text.assemble(("0", "red"))
            siem_rules_count = Text.assemble(("0", "red"))
        else:
            endpoint_rules_count = str(len(rta.endpoint_rules))
            siem_rules_count = str(len(rta.siem_rules))

        table.add_row(
            Text.assemble((rta.id, "dim")),
            rta.name,
            ", ".join(rta.platforms),
            endpoint_rules_count,
            siem_rules_count,
            ", ".join(rta.techniques),
        )
    console = Console()
    console.print(table)


@app.command()
def generate_mapping(mapping_file: Path = mapping.DEFAULT_MAPPING_FILE):
    """
    Generate a mapping file that contains rule to RTA relations.
    """
    _log = log.bind(path=str(mapping_file))
    _log.info("Generating rule-to-RTA mapping file")

    data = mapping.generate_mapping()
    with open(mapping_file, "w") as f:
        json.dump(data, f, sort_keys=True, indent=4)

    _log.info("Mapping file saved")


@app.command()
def get_coverage(rules_glob: str, with_maturity: list[str] | None = None, with_issues: bool = False):
    """
    Calculate RTA coverage for the rules with paths that match provided glob
    """
    _log = log.bind(rules_glob=rules_glob)
    _log.info("Calculating coverage against rules at provided path")

    loaded_rules = rules.load_rules(rules_glob)

    _log.info("Rules loaded", rules_count=len(loaded_rules))

    # Calculating coverage against full set of RTAs
    rules_with_issues = rules.get_coverage(loaded_rules)

    rules_to_print = [
        (rule, issues)
        for rule, issues in rules_with_issues
        # filter by maturity if `--with-maturity` criteria are set
        # filter by issues if `--with-issues` flag is set
        if ((not with_maturity or rule.maturity in with_maturity) and (not with_issues or issues))
    ]

    type_counter = Counter()  # type: ignore
    type_counter.update([r.type for r, _ in rules_to_print])  # type: ignore

    maturity_counter = Counter()  # type: ignore
    maturity_counter.update([r.maturity for r, _ in rules_to_print])  # type: ignore

    releases_counter = Counter()  # type: ignore
    releases_counter.update([release for r, _ in rules_to_print for release in r.releases])  # type: ignore

    issues_counter = Counter()  # type: ignore
    issues_counter.update([i for _, issues in rules_to_print for i in issues])  # type: ignore

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style="grey50",
        show_footer=True,
    )
    table.add_column("Rule ID", f"Total: {len(rules_to_print)}", no_wrap=True)
    table.add_column("Type", "\n".join(f"{k}: {v}" for k, v in type_counter.items()))  # type: ignore
    table.add_column("Name")
    table.add_column("Maturity", "\n".join(f"{k}: {v}" for k, v in maturity_counter.items()))  # type: ignore
    table.add_column("Releases", "\n".join(f"{k}: {v}" for k, v in releases_counter.items()))  # type: ignore
    table.add_column("Issues", "\n".join(f"{k}: {v}" for k, v in issues_counter.items()))  # type: ignore

    for rule, issues in rules_to_print:
        table.add_row(
            Text.assemble((rule.id, "dim")),
            rule.type,
            rule.name,
            rule.maturity,
            ", ".join(rule.releases or []),
            "\n".join(issues),
        )

    console = Console()
    console.print(table)


@app.callback()
def main(verbose: bool = False, logs_as_json: bool = False):
    logging_level = logging.DEBUG if verbose else logging.INFO
    configure_logging(logging_level, as_json=logs_as_json)


def run_cli():
    app()
