# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from collections import Counter
import sys
from multiprocessing import Pool

from cortado.rtas import CodeRta, get_registry, load_module
from cortado.rtas._common import get_current_os, configure_logging

log = logging.getLogger(__name__)


DUMMY_RTA_NAME = "test-rta"


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


def _run_rta_in_process(rta_name: str) -> Exception | None:
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
            return ValueError(f"Can't find RTA with name `{rta_name}`")

    except Exception as e:
        log.error(f"Can't load RTA `{rta_name}`", exc_info=True)
        return e

    if not isinstance(rta, CodeRta):
        log.warning(f"RTA `{rta_name}` is not executable")
        return ValueError(f"RTA `{rta_name}` is not executable")

    log.debug(f"Running {rta_name}")
    try:
        rta.code_func()
    except Exception as e:
        log.error(f"RTA `{rta_name}` failed during execution", exc_info=True)
        return e

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

    names_and_errors = list(zip(rta_names, errors))

    error_counter = Counter()  # type: ignore
    error_counter.update([("Failed" if e else "Succeeded") for _, e in names_and_errors])  # type: ignore

    for name, error in sorted(names_and_errors):
        if errors:
            log.info(f"Failure: `{name}`, Error: `{str(error)}`")
        else:
            log.info(f"Success: `{name}`")

    results = ", ".join([f"{k}={v}" for k, v in error_counter.items()])  # type: ignore
    log.info(f"RTA execution results: {results}")
