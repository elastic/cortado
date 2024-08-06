import enum
import functools
import importlib
import importlib.resources
from pathlib import Path
from dataclasses import dataclass, KW_ONLY, field
from typing import Callable

import logging

log = logging.getLogger(__name__)


REGISTRY = {}


class OSType(enum.StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    name: str


@dataclass(frozen=True)
class RtaDetails:
    id: str
    name: str
    platforms: list[OSType]

    _: KW_ONLY

    endpoint_rules: list[RuleMetadata] = field(default_factory=list)
    siem_rules: list[RuleMetadata] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.platforms and (self.endpoint_rules or self.siem_rules):
            raise ValueError(f"RTA {self.name} has no platforms specified but has rule info provided")


@dataclass(kw_only=True, frozen=True)
class CodeRtaDetails(RtaDetails):
    code_func: Callable[[], None]


@dataclass(kw_only=True, frozen=True)
class HashRtaDetails(RtaDetails):
    sample_hash: str


def register_code_rta(
    id: str,
    name: str,
    platforms: list[OSType],
    endpoint_rules: list[RuleMetadata] = [],
    siem_rules: list[RuleMetadata] = [],
    techniques: list[str] = [],
) -> Callable[[Callable[[], None]], Callable[[], None]]:
    def decorator(func: Callable[[], None]) -> Callable[[], None]:
        REGISTRY[name] = CodeRtaDetails(
            id=id,
            name=name,
            platforms=platforms,
            endpoint_rules=endpoint_rules,
            siem_rules=siem_rules,
            techniques=techniques,
            code_func=func,
        )
        log.debug(f"Code RTA registered: ${name}")

        @functools.wraps(func)
        def wrapper() -> None:
            func()

        return wrapper

    return decorator


def register_hash_rta(
    id: str,
    name: str,
    platforms: list[OSType],
    sample_hash: str,
    endpoint_rules: list[RuleMetadata] = [],
    siem_rules: list[RuleMetadata] = [],
    techniques: list[str] = [],
):
    REGISTRY[name] = HashRtaDetails(
        id=id,
        name=name,
        platforms=platforms,
        endpoint_rules=endpoint_rules,
        siem_rules=siem_rules,
        techniques=techniques,
        sample_hash=sample_hash,
    )
    log.debug(f"Hash RTA registered: ${name}")


def load_all():
    dir_path = importlib.resources.files("cortado.rtas")
    module_file: Path
    for module_file in dir_path.glob("*.py"):  # type: ignore
        name = module_file.stem  # type: ignore
        _ = importlib.import_module(f".{name}", package="cortado.rtas")
