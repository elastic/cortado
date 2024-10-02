# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="3ede81fa-f4e7-48fc-a939-50ad7a9a07ca",
    name="rundll32_unusual_args",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b8a0a3aa-0345-4035-b41d-f758a6c59a78", name="Command Shell Activity Started via RunDLL32"),
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="cfaf983e-1129-464c-b0aa-270f42e20d3d", name="RunDLL32 with Unusual Arguments"),
        RuleMetadata(id="f60455df-5054-49ff-9ff7-1dc4e37b6ea7", name="Binary Proxy Execution via Rundll32"),
    ],
    techniques=["T1218", "T1059"],
)
def main():
    source_dll = "C:\\Windows\\System32\\IEAdvpack.dll"
    dll = "C:\\Users\\Public\\IEAdvpack.dll"
    _common.copy_file(source_dll, dll)

    # Execute command
    log.info("Spawning cmd using Rundll32")
    _ = _common.execute_command(["rundll32.exe", f"{dll},RegisterOCX", "cmd.exe"])

    _common.remove_files([dll])
