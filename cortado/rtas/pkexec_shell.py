# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="dc1baf0d-8048-481a-b142-73313181fe31",
    name="pkexec_shell",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="30c89cc9-d93c-4134-a976-58f8413f2f32", name="Privilege Escalation via PKEXEC Exploitation")
    ],
    siem_rules=[],
    techniques=["T1574", "T1068"],
)
def main():
    log.info("Executing command to simulate privilege escalation via PKEXEC exploitation")
    # The exploit reproduction is available for commercial usage via MIT License
    # https://github.com/berdav/CVE-2021-4034/blob/main/LICENSE
    # The RTA script has complied binary in the /bin folder. Refer src folder for the origin code.

    exploit_path = _common.get_resource_path("bin", "pkexec_cve20214034/cve-2021-4034")
    _ = _common.execute_command(exploit_path)
