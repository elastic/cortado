# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="432b8bb0-03e2-4618-bda9-77c0cef7eef8",
    name="cve_2023_0386",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="22145fc0-dc4c-4187-8397-4d20162fc391", name="CVE-2023-0386 Exploitation Attempt"),
    ],
    techniques=["T1068"],
)
def main() -> None:
    masquerade = "/tmp/fuse"
    masquerade2 = "/tmp/fusermount"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = _common.get_resource_path("bin/linux_ditto_and_spawn_parent_child")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)

    # Execute command
    log.info("Executing Fake Commands to simulate CVE-2023-0386 Exploitation Attempt")
    command = f"{masquerade2} -o rw,nosuid,nodev ./* "
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10)  # noqa: S604

    # cleanup
    _common.remove_file(masquerade)
