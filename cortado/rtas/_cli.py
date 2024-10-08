import logging
from collections import Counter
import sys
import enum
from multiprocessing import Pool

from cortado.rtas import CodeRta, get_registry, load_module
from cortado.rtas._common import get_current_os, configure_logging

log = logging.getLogger(__name__)


DUMMY_RTA_NAME = "test-rta"


class RtaIssue(enum.StrEnum):
    NOT_EXECUTABLE = "RTA is not executable"
    FAILURE_DURING_LOADING = "Failure during loading"
    FAILURE_DURING_EXEC = "Failure during execution"


# CLI interface with the bare-minimum dependencies


def run_rta():
    configure_logging()

    if len(sys.argv) != 2:
        raise ValueError("RTA name argument is not provided")

    rta_to_run = sys.argv[1]
    rta_to_run = rta_to_run.strip()

    if not rta_to_run:
        raise ValueError("RTA name is not provided")

    if rta_to_run == DUMMY_RTA_NAME:
        log.info("Dummy RTA name received. The check is done")
        return

    # NOTE: we're assuming here that the RTA will be registered in the module
    # named as RTA. This might not be the case in the future.
    load_module(rta_to_run)
    registry = get_registry()

    log.info(f"RTAs loaded: {len(registry)}")

    for rta_name, rta_details in registry.items():
        if rta_name != rta_to_run:
            continue

        log.debug(f"Running `{rta_name}` RTA")

        if isinstance(rta_details, CodeRta):
            rta_details.code_func()
        else:
            log.error(f"Found an RTA but it's a hash RTA: `{rta_name}`")
            raise ValueError("Can't run a hash RTA")


def _run_rta_in_process(rta_name: str) -> RtaIssue | None:
    configure_logging()
    log = logging.getLogger(__name__)

    log.debug(f"Loading {rta_name}")

    try:
        # NOTE: we're assuming here that the RTA will be registered in the module
        # named as RTA. This might not be the case in the future.
        load_module(rta_name)
        registry = get_registry()

        rta = registry.get(rta_name)
        if not rta:
            raise ValueError(f"Can't find RTA with name `{rta_name}`")

    except Exception:
        log.error(f"Can't load RTA `{rta_name}`", exc_info=True)
        return RtaIssue.FAILURE_DURING_LOADING

    if not isinstance(rta, CodeRta):
        log.warning(f"RTA `{rta_name}` is not executable")
        return RtaIssue.NOT_EXECUTABLE

    log.debug(f"Running {rta_name}")
    try:
        rta.code_func()
    except Exception:
        log.error(f"RTA `{rta_name}` failed during execution", exc_info=True)
        return RtaIssue.FAILURE_DURING_EXEC
    return None


def run_rtas_for_os():
    configure_logging()

    if len(sys.argv) == 2:
        pool_size = int(sys.argv[1])
    else:
        pool_size = 1

    current_os = get_current_os()

    registry = get_registry()  # load all modules
    rtas_for_os = [rta for rta in registry.values() if current_os in rta.platforms]

    log.info(f"RTAs for `{current_os}`: {len(rtas_for_os)}")

    rta_names = [r.name for r in rtas_for_os]

    log.info(f"Parallel processes to run RTAs: {pool_size}")

    with Pool(pool_size) as p:
        errors = p.map(_run_rta_in_process, rta_names)

    names_and_errors = zip(rta_names, errors)

    error_counter = Counter()  # type: ignore
    error_counter.update([e for _, e in names_and_errors])  # type: ignore

    for name, error in names_and_errors:
        if errors:
            print(f"𐄂 {name}: {error}")
        else:
            print(f"✓ {name}")

    results = ", ".join([f"{k}={v}" for k, v in error_counter.items()])  # type: ignore
    log.info(f"RTA execution results: {results}")
