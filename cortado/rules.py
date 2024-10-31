import glob
import tomli
import structlog
import enum

from collections import defaultdict

from pathlib import Path
from typing import Any
from dataclasses import dataclass

from cortado.rtas import get_registry, Rta

log = structlog.get_logger(__name__)


class RuleMaturity(enum.StrEnum):
    PRODUCTION = "production"
    DEPRECATED = "deprecated"

class RuleRelease(enum.StrEnum):
    PRODUCTION = "production"
    DIAGNOSTIC = "diagnostic"


@dataclass
class Rule:
    id: str
    name: str
    type: str
    rule: dict[str, Any]

    is_endpoint_rule: bool

    path: Path

    maturity: RuleMaturity | None
    releases: list[RuleRelease]


class CoverageIssue(enum.StrEnum):
    NO_RTA = (enum.auto(), "No RTAs for the rule")
    DEPRECATED_WITH_RTA = (enum.auto(), "Rule is deprecated but has associated RTAs")

    def __new__(cls, value: str, _: str):
        obj = str.__new__(cls, value)
        obj._value_ = value
        return obj

    def __init__(self, _: str, description: str):
        self._description_ = description

    # Make sure the description is read-only
    @property
    def description(self):
        return self._description_


def load_rule(path: Path) -> Rule:
    log.debug("Loading rule", rule=str(path))
    rule_data = tomli.loads(path.read_text())
    return normalize_rule(rule_data, path)


def load_rules_from_glob(path_glob: str, skip_on_error: bool = True) -> list[Rule]:
    return load_rules_from_paths(glob.glob(path_glob), skip_on_error=skip_on_error)


def load_rules_from_paths(paths: list[str], skip_on_error: bool = True) -> list[Rule]:
    rules: list[Rule] = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            log.error("Provided rule path does not exist", path=str(p))
            raise ValueError(f"Can't read provided path: {p}")

        try:
            rule = load_rule(p)
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

    is_endpoint_rule = rule.get("rule_id") is None  # type: ignore

    rule_id: str | None = rule.get("uuid") or rule.get("rule_id")  # type: ignore
    if not rule_id:
        raise ValueError("Rule ID is not found in `rule` block in the rule body")

    rule_type = rule.get("type")  # type: ignore
    if not rule_type:
        log.debug("Rule type is not found in `rule` block in the rule body, assuming `endpoint`")
        rule_type = "endpoint"

    name = rule.get("name")  # type: ignore
    if not name:
        raise ValueError("Rule name is not found in `rule` block in the rule body")

    # Maturity is only set in the rules in `detection-rules` repo
    maturity = rule_body.get("metadata", {}).get("maturity")

    # Release labes are only set in the rules in `endpoint-rules` repo
    releases = rule_body.get("internal", {}).get("release")

    return Rule(
        id=rule_id,  # type: ignore
        name=name,  # type: ignore
        rule=rule,  # type: ignore
        type=rule_type,  # type: ignore
        path=rule_path,
        maturity=maturity,
        releases=releases or [],
        is_endpoint_rule=is_endpoint_rule,
    )


def get_coverage(rules: list[Rule], rtas: list[Rta] | None = None) -> list[tuple[Rule, list[Rta], list[CoverageIssue]]]:
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

    rules_rtas_issues: list[tuple[Rule, list[Rta], list[CoverageIssue]]] = []

    for rule in sorted(rules, key=lambda r: r.id):
        issues: list[CoverageIssue] = []

        if rule.id not in rule_to_rtas:
            issues.append(CoverageIssue.NO_RTA)

        if rule_to_rtas.get(rule.id) and rule.maturity == "deprecated":
            issues.append(CoverageIssue.DEPRECATED_WITH_RTA)

        rtas = rule_to_rtas[rule.id]
        rules_rtas_issues.append((rule, rtas, issues))

    return rules_rtas_issues
