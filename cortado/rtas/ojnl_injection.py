# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b48a9dd2-8fe7-41e1-9af2-65f609a54237",
    name="ojnl_injection",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="8fff17c6-f0ba-4996-bcc3-342a9ebd0ef3", name="Remote Code Execution via Confluence OGNL Injection"
        )
    ],
    siem_rules=[],
    techniques=["T1190"],
)
def main():
    masquerade = "/tmp/confluence/jre/fake/java"
    masquerade2 = "/tmp/bash"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = _common.get_resource_path("bin/linux_ditto_and_spawn_parent_child")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)

    # Execute command
    log.info("Launching fake commands for Remote Code Execution via Confluence")
    command = f"{masquerade2} date"
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10, kill=True, shell=True)

    # cleanup
    _common.remove_file(masquerade)
    _common.remove_file(masquerade2)
