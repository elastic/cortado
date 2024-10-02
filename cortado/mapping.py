from pathlib import Path

from typing import Any

from cortado.rtas import get_registry, load_all_modules, Rta

# File will be created / updated in the execution directory
DEFAULT_MAPPING_FILE = Path("./mapping.json")


def generate_mapping() -> list[dict[str, Any]]:
    load_all_modules()
    registry = get_registry()

    rule_to_rtas: dict[tuple[str, str, str], Rta] = {}

    for rta in registry.values():
        for siem_rule in rta.siem_rules:
            rule_to_rtas[("siem", siem_rule.id, siem_rule.name)] = rta
        for endpoint_rule in rta.siem_rules:
            rule_to_rtas[("endpoint", endpoint_rule.id, endpoint_rule.name)] = rta

    mapping_data: list[dict[str, Any]] = []

    # Sorted is applied to a key tuple inside an item tuple,
    # grouping rows by rule type and sorting by rule id
    for (rule_type, rule_id, rule_name), rta in sorted(rule_to_rtas.items()):
        mapping_data.append(
            {
                "rule_type": rule_type,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "rta_id": rta.id,
                "rta_name": rta.name,
                "rta_platforms": rta.platforms,
            }
        )

    return mapping_data
