import logging
import sys

from cortado.rtas import CodeRta, get_registry, load_module

log = logging.getLogger(__name__)


DUMMY_RTA_NAME = "test-rta"

# CLI interface with the bare-minimum dependencies


def run_rta():
    logging.basicConfig(level=logging.DEBUG)

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
