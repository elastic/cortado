# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a56d07b3-c459-4a72-adab-b93bbe008f0f",
    name="tar_dylib",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="62cc9cf4-5440-4237-aa5b-ea8db83deb3d", name="Non-Native Dylib Extracted into New Directory")
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.004"],
)
def main():
    # Execute command"
    log.info("Launching commands to tar tmp dir.")
    _ = _common.execute_command(["mkdir"], timeout_secs=10)

    with _common.temporary_file("testing", "/tmp/test.txt"):
        _ = _common.execute_command(
            ["tar", "-cf", "test.dylib", "/tmp/test.txt"],
            timeout_secs=10,
        )

    # cleanup
    _common.remove_file("test.dylib")
