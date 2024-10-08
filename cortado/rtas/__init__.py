import enum
import functools
import importlib
import importlib.resources
import logging
from dataclasses import KW_ONLY, dataclass, field, asdict
from types import MappingProxyType
from typing import Callable, Any

log = logging.getLogger(__name__)


class OSType(enum.StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


@dataclass(frozen=True)
class RuleMetadata:
    id: str
    name: str


@dataclass(frozen=True)
class Rta:
    id: str
    name: str
    platforms: list[OSType]

    # https://docs.python.org/3/library/dataclasses.html#dataclasses.KW_ONLY
    _: KW_ONLY

    endpoint_rules: list[RuleMetadata] = field(default_factory=list)
    siem_rules: list[RuleMetadata] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.platforms and (self.endpoint_rules or self.siem_rules):
            raise ValueError(f"RTA {self.name} has no platforms specified but has rule info provided")

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass(kw_only=True, frozen=True)
class CodeRta(Rta):
    code_func: Callable[[], None]
    ancillary_files: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("code_func", None)  # Drop `code_func` function as it is not serializable
        return data


@dataclass(kw_only=True, frozen=True)
class HashRta(Rta):
    sample_hash: str


_REGISTRY: dict[str, Rta] = {}


def register_code_rta(
    id: str,
    name: str,
    platforms: list[OSType],
    endpoint_rules: list[RuleMetadata] = [],
    siem_rules: list[RuleMetadata] = [],
    techniques: list[str] = [],
    ancillary_files: list[str] = [],
) -> Callable[[Callable[[], None]], Callable[[], None]]:
    def decorator(func: Callable[[], None]) -> Callable[[], None]:
        _REGISTRY[name] = CodeRta(
            id=id,
            name=name,
            platforms=platforms,
            endpoint_rules=endpoint_rules,
            siem_rules=siem_rules,
            techniques=techniques,
            code_func=func,
            ancillary_files=ancillary_files,
        )
        log.debug(f"Code RTA registered: {name}")

        @functools.wraps(func)
        def wrapper() -> None:
            # RTA code has no args
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
    _REGISTRY[name] = HashRta(
        id=id,
        name=name,
        platforms=platforms,
        endpoint_rules=endpoint_rules,
        siem_rules=siem_rules,
        techniques=techniques,
        sample_hash=sample_hash,
    )
    log.debug(f"Hash RTA registered: ${name}")


def get_registry(force_reload: bool = False) -> MappingProxyType[str, Rta]:

    if not _REGISTRY or force_reload:
        log.debug("The registry is empty or force reload is requested")
        load_all_modules()

    # Wrap a registry dict into a read-only mapping to prevent from any changes
    # https://docs.python.org/3/library/types.html#types.MappingProxyType
    return MappingProxyType(_REGISTRY)


def load_all_modules():
    dir_path = importlib.resources.files("cortado.rtas")
    log.debug(f"Loading RTA modules. dir_path={dir_path}")

    failed_imports: list[str] = []
    for module_file in dir_path.glob("*.py"):  # type: ignore
        name = module_file.stem  # type: ignore
        try:
            _ = importlib.import_module(f".{name}", package="cortado.rtas")
        except Exception:
            failed_imports.append(f"{name}")
            log.error(f"Can't import module `{name}`, skipping", exc_info=True)
            continue

    if len(failed_imports) > 0:
        log.warning(f"{len(failed_imports)} failed module imports")

    log.info(f"RTAs loaded: {len(_REGISTRY)}")


def load_module(module_name: str):
    try:
        _ = importlib.import_module(f".{module_name}", package="cortado.rtas")
    except Exception:
        raise ValueError(f"Can't import module named {module_name}")
