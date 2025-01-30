# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys

import structlog
import typer
import json
import io
import csv

from collections import Counter

from rich import box
from rich.table import Table
from rich.console import Console
from rich.text import Text

from cortado import rules
from cortado.rules import RuleMaturity, RuleRelease
from cortado.rtas import get_registry, HashRta
from cortado.utils import configure_logging

from typing import Any
from typing_extensions import Annotated


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
def get_coverage(
    rules_glob: Annotated[str | None, typer.Option(help="A path glob that resolves into rule paths")] = None,
    rule_paths_csv: Annotated[str | None, typer.Option("--rules", help="Comma-separated list of rule paths")] = None,
    filter_by_maturity: Annotated[
        list[RuleMaturity] | None,
        typer.Option(help="Filter rules by maturity (`production`, `deprecated`). Supports multiple values."),
    ] = None,
    filter_by_release: Annotated[
        list[RuleRelease] | None,
        typer.Option(help="Filter rules by release (`production`, `diagnostic`). Supports multiple values."),
    ] = None,
    filter_by_type: Annotated[
        list[str] | None,
        typer.Option(help="Filter rules by rule type. Supports multiple values."),
    ] = None,
    filter_by_rta: Annotated[
        list[str] | None,
        typer.Option(help="Filter rules by RTAs. Supports multiple values."),
    ] = None,
    with_issues: Annotated[bool, typer.Option(help="Only show rules with issues")] = False,
    without_issues: Annotated[bool, typer.Option(help="Only show rules without issues")] = False,
    as_json: Annotated[bool, typer.Option(help="Output results in JSON")] = False,
    fail_if_issues: Annotated[bool, typer.Option(help="Return status code 1 if any issues found")] = False,
):
    """
    Calculate RTA coverage for the rules with paths that match provided glob
    """

    if rule_paths_csv:
        reader = csv.reader(io.StringIO(rule_paths_csv))
        rule_paths = next(reader)
    else:
        rule_paths = []

    if not rules_glob and not rule_paths:
        raise ValueError("Either `--rules-glob` or `--rules` values must be provided")

    _log = log.bind(rules_glob=rules_glob, rules_paths=rule_paths)
    _log.info("Calculating coverage against rules at provided path")

    if rules_glob:
        loaded_rules = rules.load_rules_from_glob(rules_glob)
    else:
        loaded_rules = rules.load_rules_from_paths(rule_paths)

    _log.info("Rules loaded", rules_count=len(loaded_rules))

    # Calculating coverage against full set of RTAs
    rules_rtas_issues = rules.get_coverage(loaded_rules)

    rules_to_print = [
        (rule, rtas, issues)
        for rule, rtas, issues in rules_rtas_issues
        # filter by maturity if `--with-maturity` criteria are set
        # filter by issues if `--with-issues` flag is set
        if (
            (not filter_by_maturity or rule.maturity in filter_by_maturity)
            and (not filter_by_release or (set(filter_by_release) & set(rule.releases)))
            and (not filter_by_type or rule.type in filter_by_type)
            and (not filter_by_rta or (set(filter_by_rta) & set([r.name for r in rtas])))
            and (
                (with_issues and issues) or (without_issues and not issues) or (not with_issues and not without_issues)
            )
        )
    ]

    type_counter = Counter()  # type: ignore
    type_counter.update([r.type for r, _, _ in rules_to_print])  # type: ignore

    maturity_counter = Counter()  # type: ignore
    maturity_counter.update([r.maturity for r, _, _ in rules_to_print if r.maturity])  # type: ignore

    releases_counter = Counter()  # type: ignore
    releases_counter.update([release for r, _, _ in rules_to_print for release in r.releases])  # type: ignore

    issues_counter = Counter()  # type: ignore
    issues_counter.update([i for _, _, issues in rules_to_print for i in issues])  # type: ignore

    if as_json:
        data = {  # type: ignore
            "rule_types_counts": type_counter,
            "maturity_counts": maturity_counter,
            "releases_counts": releases_counter,
            "issues_counts": issues_counter,
            "rules": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "type": rule.type,
                    "maturity": rule.maturity,
                    "language": rule.language,  # type: ignore
                    "releases": rule.releases or [],
                    "path": str(rule.path),
                    "issues": [
                        {
                            "name": i.name.lower(),
                            "type": "coverage_issue",
                        }
                        for i in issues
                    ],  # type: ignore
                    "is_endpoint_rule": rule.is_endpoint_rule,
                    "rtas": [
                        {
                            "id": r.id,
                            "name": r.name,
                            "platforms": r.platforms,
                            **(
                                {"sample_hash": r.sample_hash} if isinstance(r, HashRta) else {}
                            ),  # set `sample_hash` only for HashRtas
                        }
                        for r in rtas
                    ],
                }
                for rule, rtas, issues in rules_to_print
            ],
        }
        print(json.dumps(data, sort_keys=True))
        _log.info("Coverage created", issues={str(k): v for k, v in issues_counter.items()})  # type: ignore
        if fail_if_issues and issues_counter:
            sys.exit(1)

        return

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL,
        border_style="grey50",
        show_footer=True,
    )
    table.add_column("Rule ID", f"Total: {len(rules_to_print)}", no_wrap=True, max_width=14)
    table.add_column("Name")
    table.add_column("File")
    table.add_column("Type", "\n".join(f"{k}: {v}" for k, v in type_counter.items()))  # type: ignore

    if maturity_counter:
        table.add_column("Maturity", "\n".join(f"{k}: {v}" for k, v in maturity_counter.items()))  # type: ignore

    if releases_counter:
        table.add_column("Releases", "\n".join(f"{k}: {v}" for k, v in releases_counter.items()))  # type: ignore

    table.add_column("RTAs")
    table.add_column("Issues", "\n".join(f"{k._description_}: {v}" for k, v in issues_counter.items()))  # type: ignore

    for rule, rtas, issues in rules_to_print:
        row = [
            Text.assemble((rule.id, "dim")),
            rule.name,
            f"{rule.path.parent.name}/{rule.path.name}",
            rule.type,
            rule.maturity if maturity_counter else None,
            ", ".join(rule.releases or []) if releases_counter else None,
            ", ".join([r.name for r in rtas]) or "-",
            "\n".join([i.description for i in issues]),  # type: ignore
        ]
        row = filter(None, row)
        table.add_row(*row)

    console = Console()
    console.print(table)
    if fail_if_issues and issues_counter:
        sys.exit(1)


@app.callback()
def main(verbose: bool = False, logs_as_json: bool = False):
    logging_level = logging.DEBUG if verbose else logging.INFO
    configure_logging(logging_level, as_json=logs_as_json)


def run_cli():
    app()
