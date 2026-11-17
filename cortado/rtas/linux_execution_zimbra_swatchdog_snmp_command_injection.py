# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Zimbra Swatchdog SNMP Command Injection Execution
# RTA: linux_execution_zimbra_swatchdog_snmp_command_injection.py
# Description: Creates the process lineage expected from a vulnerable Zimbra
#              Swatchdog script: Perl -> shell -> benign echo. The shell command
#              line contains inert snmptrap and Zimbra service-field markers.
#              It does not invoke snmptrap, exploit Zimbra, or use the network.

import logging
import tempfile
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

SHELL_COMMAND = ": snmptrap zmservicename zmservicestatus; " "/bin/echo elastic-rta-zimbra-swatchdog; " "wait"


@register_code_rta(
    id="8c0df415-8475-4f56-9f16-36d9327925ae",
    name="linux_execution_zimbra_swatchdog_snmp_command_injection",
    platforms=[OSType.LINUX],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1fa1a434-75a7-4c58-9bef-331d62bf3f82",
            name="Zimbra Swatchdog SNMP Command Injection Execution",
        )
    ],
    techniques=["T1190", "T1059.004"],
)
def main() -> None:
    """Create an inert Perl -> shell -> echo process sequence."""
    script_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix=".swatchdog_script-",
            suffix=".pl",
            delete=False,
        ) as script:
            script_path = Path(script.name)
            _ = script.write(
                "use strict;\n"
                "use warnings;\n"
                f"system('/bin/sh', '-c', '{SHELL_COMMAND}');\n"
                "exit($? == 0 ? 0 : 1);\n"
            )

        log.info("Launching inert Zimbra Swatchdog process simulation")
        _ = _common.execute_command(["perl", script_path])
        log.info("RTA process sequence completed")
    finally:
        if script_path is not None:
            _common.remove_file(script_path)
