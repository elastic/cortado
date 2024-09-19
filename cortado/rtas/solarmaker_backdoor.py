# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="c2786f8d-d565-494d-84e2-5dcb2da711c4",
    name="solarmaker_backdoor",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="f7e6d239-9af5-42e3-8d23-91e7188a5cb0", name="SolarMarker Backdoor Registry Modification")
    ],
    siem_rules=[],
    techniques=["T1112", "T1546"],
)
def main():
    reg = "C:\\Windows\\System32\\reg.exe"

    payloadcontent = (
        "Just some Powershell random words to make it to the 200 characters, remember to drink water and"
        "take a walk twice a day, check if your dog has enought food and water too, ah, and go to the"
        "gym, you can do it!!!!"
    )
    regpath = "HKEY_CURRENT_USER\\Software\\Classes\\simul8\\shell\\open"

    # Execute command
    log.info("Creating reg key using fake msiexec")
    _ = _common.execute_command(
        [
            reg,
            "add",
            regpath,
            "/v",
            "command",
            "/t",
            "REG_SZ",
            "/d",
            payloadcontent,
            "/f",
        ],
        timeout_secs=5,
        kill=True,
    )

    _ = _common.execute_command([reg, "delete", regpath, "/f"], timeout_secs=5)
