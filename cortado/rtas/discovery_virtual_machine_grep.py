# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="92407d57-e5ce-41b1-933a-7cad26158802",
    name="discovery_virtual_machine_grep",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="e5c0963c-0367-4d24-bdf2-5af3a233e57b", name="Potential Virtual Machine Fingerprinting via Grep"
        )
    ],
    siem_rules=[
        RuleMetadata(id="c85eb82c-d2c8-485c-a36f-534f914b7663", name="Virtual Machine Fingerprinting via Grep")
    ],
    techniques=["T1082", "T1497"],
)
def main():
    log.info("Executing egrep commands to fingerprint virtual machine.")
    _ = _common.execute_command(["egrep", "-i", '"Manufacturer: (parallels|vmware|virtualbox)"'])
