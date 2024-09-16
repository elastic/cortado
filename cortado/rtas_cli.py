import sys
import logging

from cortado.rtas import load_module, get_registry, CodeRta

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

# CLI interface with the bare-minimum dependencies

def run_rta():
    if len(sys.argv) != 2:
        log.error("RTA name argument is not provided")
        sys.exit(1)

    rta_to_run = sys.argv[1]
    rta_to_run = rta_to_run.strip()

    if not rta_to_run:
        log.error("RTA name is not provided")
        sys.exit(1)

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
            log.error("`{rta_name}` is a hash RTA that can't be executed")
            sys.exit(1)

