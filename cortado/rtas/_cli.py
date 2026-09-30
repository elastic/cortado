# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import argparse
import logging
import os
import sys
import time
from collections import Counter
from multiprocessing import Pool
from typing import Mapping

from cortado.rtas import CodeRta, MultiHostRta, OSType, Rta, get_registry, load_module
from cortado.rtas._common import configure_logging, get_current_os

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
    try:
        load_module(rta_to_run)
    except ValueError as e:
        from cortado.rtas._multihost import MultiHostError, get_multihost_rta

        try:
            _ = get_multihost_rta(rta_to_run)
        except MultiHostError:
            raise e
        raise ValueError(
            f"`{rta_to_run}` is a multi-host RTA, run it with `cortado-run-multihost-rta run {rta_to_run} --role ROLE`"
        )
    registry = get_registry()

    log.info(f"RTAs loaded: {len(registry)}")

    for rta_name, rta_details in registry.items():
        if rta_name != rta_to_run:
            continue

        log.debug(f"Running `{rta_name}` RTA")

        if isinstance(rta_details, CodeRta):
            rta_details.code_func()
            return
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


def get_single_host_rtas_for_os(registry: Mapping[str, Rta], current_os: OSType) -> list[Rta]:
    # Multi-host RTAs wait for peers on other hosts, so they're never part of a single-host batch run
    return [rta for rta in registry.values() if current_os in rta.platforms and not isinstance(rta, MultiHostRta)]


def run_rtas_for_os():
    configure_logging()

    if len(sys.argv) == 2:
        pool_size = int(sys.argv[1])
    else:
        pool_size = 1

    current_os = get_current_os()

    registry = get_registry()  # load all modules
    rtas_for_os = get_single_host_rtas_for_os(registry, current_os)

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


# Multi-host RTA CLI (stdlib only, like the rest of the RTA CLI)


def _build_multihost_parser() -> argparse.ArgumentParser:
    from cortado.rtas._multihost import DEFAULT_TIMEOUT_SECS, SECRET_ENV_VAR

    parser = argparse.ArgumentParser(
        prog="cortado-run-multihost-rta",
        description="Run multi-host RTAs: each role runs on its own host and roles coordinate through the operator "
        "(default), an orchestrator (`cortado run-multihost`), or locally over loopback (`--local`).",
    )
    _ = parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    commands = parser.add_subparsers(dest="command", required=True)

    _ = commands.add_parser("list", help="List multi-host RTAs")

    describe = commands.add_parser("describe", help="Show roles, parameters, and example commands of an RTA")
    _ = describe.add_argument("name")

    run = commands.add_parser(
        "run",
        help="Run one role of an RTA (or all roles with --local)",
        epilog=f"The shared secret is taken from --secret, --secret-stdin, or ${SECRET_ENV_VAR}. "
        "Listening roles generate one if none is given and print the commands to run on peer hosts.",
    )
    _ = run.add_argument("name")
    target = run.add_mutually_exclusive_group(required=True)
    _ = target.add_argument("--role", help="Role to run on this host")
    _ = target.add_argument("--local", action="store_true", help="Run all roles on this host over loopback")
    _ = run.add_argument(
        "--bind", default="127.0.0.1", help="Address listening roles bind to (use 0.0.0.0 for a second host)"
    )
    _ = run.add_argument("--port", type=int, help="Port to listen on or connect to (default: RTA-specific)")
    _ = run.add_argument(
        "--peer", action="append", default=[], metavar="[ROLE=]HOST[:PORT]", help="Address of a listening peer role"
    )
    _ = run.add_argument(
        "-p", "--param", action="append", default=[], metavar="NAME=VALUE", help="Set an RTA parameter"
    )
    _ = run.add_argument("--run-id", help="Identifier shared by all roles of one run (default: generated)")
    _ = run.add_argument("--secret", help=f"Shared secret, 16-64 bytes (prefer ${SECRET_ENV_VAR})")
    _ = run.add_argument("--secret-stdin", action="store_true", help="Read the shared secret from the first stdin line")
    _ = run.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT_SECS, help="Maximum role run time in seconds"
    )
    coordination = run.add_mutually_exclusive_group()
    _ = coordination.add_argument(
        "--no-wait", action="store_true", help="Don't wait for peer signals (continue immediately)"
    )
    _ = coordination.add_argument(
        "--driven", action="store_true", help="Read peer signals from stdin (used by `cortado run-multihost`)"
    )
    return parser


def _print_multihost_list() -> int:
    from cortado.rtas._multihost import get_multihost_rtas

    rtas = get_multihost_rtas()
    rows = [("NAME", "ROLES", "PLATFORMS", "RULES")]
    for rta in rtas:
        roles = ", ".join(f"{r.name}{'*' if r.listens else ''}" for r in rta.roles.values())
        rows.append((rta.name, roles, ", ".join(rta.platforms), str(len(rta.siem_rules) + len(rta.endpoint_rules))))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())
    print("\n* listening role (start it first)")
    return 0


def _print_multihost_description(name: str) -> int:
    from cortado.rtas._multihost import get_multihost_rta

    rta = get_multihost_rta(name)
    print(f"{rta.name} ({rta.id})")
    print(f"  platforms: {', '.join(rta.platforms)}")
    print(f"  techniques: {', '.join(rta.techniques) or '-'}")
    for kind, rules in (("siem rules", rta.siem_rules), ("endpoint rules", rta.endpoint_rules)):
        print(f"  {kind}: {', '.join(r.name for r in rules) or '-'}")

    print("\nroles:")
    for role in rta.roles.values():
        listens = " (listening, start first)" if role.listens else ""
        print(f"  {role.name}{listens} [{', '.join(role.platforms)}]")
        if role.help:
            print(f"      {role.help}")

    print("\nparameters:")
    for param in rta.parameters:
        choices = f" {{{'|'.join(param.choices)}}}" if param.choices else ""
        print(f"  {param.name}{choices} (default: {param.default})")
        if param.help:
            print(f"      {param.help}")

    listening = [r.name for r in rta.roles.values() if r.listens]
    print("\nexample:")
    print(f"  cortado-run-multihost-rta run {rta.name} --local")
    for role in rta.roles.values():
        peer = "" if role.listens or not listening else f" --peer {listening[0]}=LISTENER_IP"
        bind = " --bind 0.0.0.0" if role.listens else ""
        print(f"  cortado-run-multihost-rta run {rta.name} --role {role.name}{bind}{peer}")
    return 0


def _run_multihost(args: argparse.Namespace) -> int:
    from cortado.rtas._multihost import (
        SECRET_ENV_VAR,
        EventWriter,
        MultiHostError,
        RoleContext,
        StdinCoordinator,
        StdinLines,
        generate_run_id,
        generate_secret,
        get_multihost_rta,
        parse_assignments,
        parse_peers,
        resolve_params,
        run_local,
        run_role,
        validate_secret,
    )

    rta = get_multihost_rta(args.name)
    overrides = parse_assignments(args.param)
    params = resolve_params(rta, overrides)

    if args.local:
        return run_local(rta, params, timeout=args.timeout, port=args.port, run_id=args.run_id)

    role = rta.roles.get(args.role)
    if role is None:
        raise MultiHostError(f"Unknown role `{args.role}`, roles of `{rta.name}`: {', '.join(rta.roles)}")

    peers = parse_peers(args.peer, rta, role)
    if not role.listens and not peers:
        raise MultiHostError(f"Role `{role.name}` connects to a listening role, pass its address with `--peer`")

    lines = StdinLines() if args.driven or args.secret_stdin else None
    if args.secret_stdin:
        assert lines is not None
        secret = lines.readline(args.timeout)
        if not secret:
            raise MultiHostError("No secret received on stdin")
    else:
        secret = args.secret or os.environ.get(SECRET_ENV_VAR)
    if not secret:
        if not role.listens:
            raise MultiHostError(f"Pass the secret printed by the listening role via ${SECRET_ENV_VAR} or --secret")
        secret = generate_secret()

    mode = "driven" if args.driven else "no-wait" if args.no_wait else "manual"
    ctx = RoleContext(
        rta=rta,
        role=role,
        run_id=args.run_id or generate_run_id(),
        params=params,
        secret=validate_secret(secret),
        deadline=time.monotonic() + args.timeout,
        coordinator=StdinCoordinator(mode, lines),
        events=EventWriter(),
        bind_host=args.bind,
        port=args.port,
        peers=peers,
        param_overrides=overrides,
    )
    return run_role(ctx)


def run_multihost_rta(argv: list[str] | None = None) -> None:
    from cortado.rtas._multihost import MultiHostError

    args = _build_multihost_parser().parse_args(argv)
    # Logs go to stderr; stdout is reserved for JSON events
    configure_logging(logging.DEBUG if args.verbose else logging.INFO)

    try:
        if args.command == "list":
            code = _print_multihost_list()
        elif args.command == "describe":
            code = _print_multihost_description(args.name)
        else:
            code = _run_multihost(args)
    except MultiHostError as e:
        log.error(str(e))
        code = 2
    sys.exit(code)
