# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="1d7ff305-03b5-4917-b32c-d0267018063c",
    name="hidden_file_mount",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="c5f219ca-4bda-461b-bc54-246c0bb48143", name="MacOS Hidden File Mounted"),
    ],
    siem_rules=[],
    techniques=["T1211", "T1059", "T1059.004"],
)
def main():
    mount_dir = "/tmp/.exploit"
    disk_file = "disk.dmg"

    # create disk image
    _ = _common.execute_command(["hdiutil", "create", "-size", "50b", "-volname", ".exploit", "-ov", disk_file])

    # attach disk image to mount point
    log.info("Launching hdutil commands to mount dummy dmg")
    _ = _common.execute_command(
        ["hdiutil", "attach", "-mountpoint", mount_dir, disk_file],
    )

    # cleanup
    _ = _common.execute_command(["hdiutil", "eject", "/tmp/.exploit"], timeout_secs=10, kill=True)
    _common.remove_file(disk_file)
