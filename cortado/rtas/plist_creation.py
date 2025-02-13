# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import time
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


def pause():
    time.sleep(1)


@register_code_rta(
    id="12e70377-e24e-4374-8aec-42064614d706",
    name="plist_creation",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(
            id="901f0c30-a7c5-40a5-80e3-a50c6714432f", name="Suspicious Property List File Creation or Modification"
        )
    ],
    techniques=["T1547", "T1543"],
)
def main():
    launch_agents_dir = Path.home() / "Library" / "Launchagents"
    plistbuddy_bin = "/usr/libexec/PlistBuddy"
    plist_file = Path.home() / "Library" / "Launchagents" / "init_verx.plist"

    # Create launch agents dir if it doesn't exist
    if not launch_agents_dir.exists():
        log.info(f"Creating directory {launch_agents_dir}")
        launch_agents_dir.mkdir()

    # Create plist file using Plistbuddy
    log.info("Executing PlistBuddy commands to create plist file")
    _ = _common.execute_command(
        [f"{plistbuddy_bin}", "-c", "Add :Label string init_verx", f"{plist_file}"],
        shell=True,
    )
    pause()
    _ = _common.execute_command([f"{plistbuddy_bin}", "-c", "Add :RunAtLoad bool true", f"{plist_file}"])
    pause()
    _ = _common.execute_command([f"{plistbuddy_bin}", "-c", "Add :StartInterval integer 3600", f"{plist_file}"])
    pause()
    _ = _common.execute_command([f"{plistbuddy_bin}", "-c", "Add :ProgramArguments array", f"{plist_file}"])
    pause()
    _ = _common.execute_command(
        [
            f"{plistbuddy_bin}",
            "-c",
            "Add :ProgramArguments:0 string '/bin/sh'",
            f"{plist_file}",
        ]
    )
    pause()
    _ = _common.execute_command(
        [
            f"{plistbuddy_bin}",
            "-c",
            "Add :ProgramArguments:1 string -c",
            f"{plist_file}",
        ]
    )

    # Delete the plist file if it exists
    if plist_file.exists():
        log.info(f"Deleting plist file {plist_file}")
        plist_file.unlink()
