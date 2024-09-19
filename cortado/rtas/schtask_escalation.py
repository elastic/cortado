# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Scheduled Task Privilege Escalation
# RTA: schtask_escalation.py
# signal.rule.name: Local Scheduled Task Commands
# signal.rule.name: Whoami Process Activity
# signal.rule.name: Svchost spawning Cmd
# signal.rule.name: Net command via SYSTEM account
# ATT&CK: T1053

import logging
import time
from pathlib import Path
from typing import Any

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


def execute_schtasks(args: list[str], kwargs: dict[str, Any] = {}) -> int:
    retcode, _, _ = _common.execute_command(["schtasks.exe"] + args, **kwargs)
    return retcode


@register_code_rta(
    id="1a61241e-5b1b-44ec-8c9f-3ae4652550be",
    name="schtask_escalation",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="afcce5ad-65de-4ed2-8516-5e093d3ac99a", name="Local Scheduled Task Creation"),
        RuleMetadata(id="ef862985-3f13-4262-a686-5f357bbb9bc2", name="Whoami Process Activity"),
        RuleMetadata(id="fd7a6052-58fa-4397-93c3-4795249ccfa2", name="Svchost spawning Cmd"),
    ],
    techniques=["T1033", "T1053", "T1059"],
)
def main():
    log.info("Scheduled Task Privilege Escalation")

    task_name = "test-task-rta"
    file_path = Path("task.log").resolve()
    command = f"cmd.exe /c whoami.exe > {file_path}"

    # Delete the task if it exists
    retcode = execute_schtasks(["/query", "/tn", task_name])
    if retcode == 0:
        _ = execute_schtasks(["/delete", "/tn", task_name, "/f"])

    retcode = execute_schtasks(["/create", "/tn", task_name, "/ru", "system", "/tr", command, "/sc", "onlogon"])
    if retcode != 0:
        log.info("Error creating task")
        return

    # Run the task and grab the file
    retcode = execute_schtasks(["/run", "/tn", task_name])
    if retcode == 0:
        time.sleep(1)
        _common.print_file(file_path)
        time.sleep(1)
        _common.remove_file(file_path)

    _ = execute_schtasks(["/delete", "/tn", task_name, "/f"])
