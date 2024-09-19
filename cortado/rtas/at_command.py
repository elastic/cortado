# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: AT Command Lateral Movement
# RTA: at_command.py
# ATT&CK: T1053
# Description: Enumerates at tasks on target host, and schedules an at job for one hour in the future. Then checks the
#  status of that task, and deletes the task.

import datetime
import logging
import re

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="961d7a1f-7bad-41d5-a3d9-8e8a2f59a824",
    name="at_command",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[],
    techniques=[],
)
def main():
    target_host = _common.get_host_ip()
    host_str = "\\\\%s" % target_host

    # Current time at \\localhost is 11/16/2017 11:25:50 AM
    _, output, _ = _common.execute_command(["net", "time", host_str])

    if not output:
        raise _common.ExecutionError("Can't get time from the host")

    output_str = output.decode("utf-8")
    match = re.search(r"Current time at .*? is (\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+) (AM|PM)", output_str)
    if not match:
        raise _common.ExecutionError("No matches found in `net time` output")

    groups = match.groups()
    m, d, y, hh, mm, ss, period = groups
    now = datetime.datetime(
        month=int(m),
        day=int(d),
        year=int(y),
        hour=int(hh),
        minute=int(mm),
        second=int(ss),
    )
    if period == "PM" and hh != "12":
        now += datetime.timedelta(hours=12)

    # Add one hour
    task_time = now + datetime.timedelta(hours=1)

    # Round down minutes
    time_string = "%d:%d" % (task_time.hour, task_time.minute)

    # Enumerate all remote tasks
    _ = _common.execute_command(["at.exe", host_str])

    # Create a job 1 hour into the future
    retcode, output, stderr = _common.execute_command(["at", host_str, time_string, "cmd /c echo hello world"])

    if not output:
        raise _common.ExecutionError("No output from `at` command")

    output_str = output.decode("utf-8")

    if retcode == 1 and "deprecated" in output_str:
        log.error(f"Error while running `at`, not supported in this version of Windows: {output_str}")
        raise _common.ExecutionError("Error while running `at`")

    if retcode != 0:
        log.error(f"Error while running `at`: {stderr}")
        raise _common.ExecutionError("Error while running `at`")

    match = re.search(r"ID = (\d+)", output_str)
    if not match:
        raise _common.ExecutionError("No matches in `at` output")

    job_id = match.group(1)

    # Check status and delete
    _ = _common.execute_command(["at.exe", host_str, job_id])
    _ = _common.execute_command(["at.exe", host_str, job_id, "/delete"])
