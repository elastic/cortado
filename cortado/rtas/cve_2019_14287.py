# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="df91f5f2-a0a0-47e8-848b-d01526a43d60",
    name="cve_2019_14287",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="b382c343-892d-46e1-8fad-22576a086598", name="Potential Sudo Privilege Escalation via CVE-2019-14287"
        )
    ],
    siem_rules=[
        RuleMetadata(
            id="8af5b42f-8d74-48c8-a8d0-6d14b4197288", name="Potential Sudo Privilege Escalation via CVE-2019-14287"
        )
    ],
    techniques=["T1068"],
)
def main():
    masquerade = "/tmp/sudo"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake sudo command to simulate CVE-2019-14287")
    _ = _common.execute_command([masquerade, "-u#-1"], timeout_secs=5)

    # cleanup
    _common.remove_file(masquerade)
