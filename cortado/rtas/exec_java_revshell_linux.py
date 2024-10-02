# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e0db3577-879e-4ac2-bd58-691e1343afca",
    name="exec_java_revshell_linux",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="e0db3577-879e-4ac2-bd58-691e1343afca", name="Potential Linux Reverse Shell via Java")
    ],
    techniques=["T1059", "T1071"],
)
def main():
    log.info("Creating a fake Java executable..")
    masquerade = "/bin/java"
    source = _common.get_resource_path("bin/netcon_exec_chain.elf")
    _common.copy_file(source, masquerade)

    log.info("Granting execute permissions...")
    _ = _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "chain", "-h", "127.0.0.1", "-p", "1337", "-c", "-jar"]

    log.info("Simulating reverse shell activity..")
    _ = _common.execute_command([*commands], timeout_secs=5)
    log.info("Reverse shell simulation successful!")
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("RTA completed!")
