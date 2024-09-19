# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="44345dc0-883f-41b7-ad34-1d84cfd57129",
    name="calendar_file_mod",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="cb71aa62-55c8-42f0-b0dd-afb0bb0b1f51", name="Suspicious Calendar File Modification")],
    techniques=["T1546"],
)
def main():
    cal_dir = Path(f"{Path.home()}/Library/Calendars/")
    cal_calendar = cal_dir.joinpath("test.calendar", "Events")
    cal_calendar.mkdir(parents=True, exist_ok=True)
    cal_path = str(cal_calendar.joinpath("test.ics"))
    log.info(f"Executing file modification on {cal_path} to mimic suspicious calendar file modification")
    _common.create_file_with_data(cal_path, "testing")

    # cleanup
    _common.remove_directory(str(cal_calendar))
    _common.remove_directory(str(cal_dir))
