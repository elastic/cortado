# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, register_code_rta, OSType, RuleMetadata


@register_code_rta(
    id="432b8bb0-03e2-4618-bda9-77c0cef7eef8",
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
    source = _common.get_path("bin", "linux_ditto_and_spawn_parent_child")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)

    # Execute command
    _common.log("Executing Fake Commands to simulate CVE-2023-0386 Exploitation Attempt")
    command = f"{masquerade2} -o rw,nosuid,nodev ./* "
    _common.execute([masquerade, "childprocess", command], timeout=10, kill=True, shell=True)  # noqa: S604

    # cleanup
    _common.remove_file(masquerade)
