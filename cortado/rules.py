import glob
import tomli
import structlog

from collections import defaultdict

from pathlib import Path
from typing import Any, Literal
from dataclasses import dataclass

from cortado.rtas import get_registry, Rta

log = structlog.get_logger(__name__)


@dataclass
class Rule:
    id: str
    name: str
    type: str
    rule: dict[str, Any]

    path: Path

    maturity: Literal["production", "deprecated"] | None
    releases: list[Literal["production", "diagnostic"]] | None


def load_rule(path: Path) -> Rule:
    log.debug("Loading rule", rule=str(path))
    rule_data = tomli.loads(path.read_text())
    return normalize_rule(rule_data, path)


def load_rules(path_glob: str, skip_on_error: bool = True) -> list[Rule]:
    rules: list[Rule] = []
    for path in glob.glob(path_glob):
        try:
            rule = load_rule(Path(path))
        except ValueError as e:
            if skip_on_error:
                log.warning("Error while reading a rule, skipping", rule=path, error=e)
                continue
            raise
        rules.append(rule)
    return rules


def normalize_rule(rule_body: dict[str, Any], rule_path: Path) -> Rule:
    rule = rule_body.get("rule")

    if not rule:
        raise ValueError("No `rule` block found in the rule body")

    if not isinstance(rule, dict):
        raise ValueError("Unknown value for `rule` in the rule body")

    # `rule_id` in `detection-rules`
    # `uuid` in `endpoint-rules`
    rule_id: str | None = rule.get("uuid") or rule.get("rule_id")  # type: ignore
    if not rule_id:
        raise ValueError("Rule ID is not found in `rule` block in the rule body")

    rule_type = rule.get("type")  # type: ignore
    if not rule_type:
        raise ValueError("Rule type is not found in `rule` block in the rule body")

    name = rule.get("name")  # type: ignore
    if not name:
        raise ValueError("Rule name is not found in `rule` block in the rule body")

    # Maturity is only set in the rules in `detection-rules` repo
    maturity = rule_body.get("metadata", {}).get("maturity")

    # Release labes are only set in the rules in `endpoint-rules` repo
    release = rule_body.get("internal", {}).get("release")

    return Rule(
        id=rule_id,  # type: ignore
        name=name,  # type: ignore
        rule=rule,  # type: ignore
        type=rule_type,  # type: ignore
        path=rule_path,
        maturity=maturity,
        releases=release,
    )


def get_coverage(rules: list[Rule], rtas: list[Rta] | None = None) -> list[tuple[Rule, list[str]]]:
    rtas = rtas or list(get_registry().values())

    rule_to_rtas: dict[str, list[Rta]] = defaultdict(list)
    for rta in rtas:
        for siem_rule in rta.siem_rules:
            rule_to_rtas[siem_rule.id].append(rta)

        for endpoint_rule in rta.endpoint_rules:
            rule_to_rtas[endpoint_rule.id].append(rta)

        if not rta.siem_rules and not rta.endpoint_rules:
            log.debug("RTA without any rules found, skipping", id=rta.id, name=rta.name)
            continue

    issue_rule_without_rta = "No RTAs for the rule"
    issue_deprecated_rule_with_rtas = "Rule is deprecated but has associated RTAs"
    rules_with_issues: list[tuple[Rule, list[str]]] = []

    for rule in sorted(rules, key=lambda r: r.id):
        issues: list[str] = []

        if rule.id not in rule_to_rtas:
            issues.append(issue_rule_without_rta)

        if rule_to_rtas.get(rule.id) and rule.maturity == "deprecated":
            issues.append(issue_deprecated_rule_with_rtas)

        rules_with_issues.append((rule, issues))

    return rules_with_issues
