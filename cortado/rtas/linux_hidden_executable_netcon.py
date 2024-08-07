# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="da45a71e-fc97-492d-932f-703b11c08387",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="04ec0ec4-86c4-47e3-8c7b-8dad5f97532c", name="Hidden Process Execution followed by Network Connection"
        )
    ],
    techniques=["T1105", "T1071"],
)
def main():
    _common.log("Creating a fake hidden executable..")
    masquerade = "/tmp/.evil"
    source = _common.get_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)
    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "netcon", "-h", "8.8.8.8", "-p", "53"]
    _common.execute([*commands], timeout=5, kill=True)
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("Simulation successfull!")
