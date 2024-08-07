# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="e0db3577-879e-4ac2-bd58-691e1343afca",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="e0db3577-879e-4ac2-bd58-691e1343afca", name="Potential Linux Reverse Shell via Java")
    ],
    siem_rules=[],
    techniques=["T1059", "T1071"],
)
def main():
    _common.log("Creating a fake Java executable..")
    masquerade = "/bin/java"
    source = _common.get_path("bin", "netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)

    _common.log("Granting execute permissions...")
    _common.execute(["chmod", "+x", masquerade])

    commands = [masquerade, "chain", "-h", "127.0.0.1", "-p", "1337", "-c", "-jar"]

    _common.log("Simulating reverse shell activity..")
    _common.execute([*commands], timeout=5)
    _common.log("Reverse shell simulation successful!")
    _common.log("Cleaning...")
    _common.remove_file(masquerade)
    _common.log("RTA completed!")
