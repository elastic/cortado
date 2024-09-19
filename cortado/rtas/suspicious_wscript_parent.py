# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious WScript parent
# RTA: suspicious_wscript_parent.py
# signal.rule.name: Suspicious MS Outlook Child Process
# ATT&CK: T1064, T1192, T1193
# Description: WScript run with suspicious parent processes

import logging
import time
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="a3cdd478-b817-4513-bb3d-897a5f92c836",
    name="suspicious_wscript_parent",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="32f4675e-6c49-4ace-80f9-97c9259dca2e", name="Suspicious MS Outlook Child Process"),
        RuleMetadata(id="a624863f-a70d-417f-a7d2-7a404638d47f", name="Suspicious MS Office Child Process"),
    ],
    techniques=["T1566"],
)
def main():
    script_data = """
        WScript.CreateObject("wscript.shell")
    """
    script_path = ".\\hello.vbs"
    with open(script_path, "w") as f:
        f.write(script_data)

    cmd_path = "c:\\windows\\system32\\cmd.exe"

    for application in ["outlook.exe", "explorer.exe", "chrome.exe", "firefox.exe"]:
        log.info("Emulating %s" % application)
        app_path = Path(application).resolve()
        _common.copy_file(cmd_path, app_path)

        _ = _common.execute_command([app_path, "/c", "wscript.exe", "script_path"], timeout_secs=1)

        log.info("Killing wscript window")
        _ = _common.execute_command("taskkill /IM wscript.exe")

        log.info("Cleanup %s" % app_path)
        _common.remove_file(app_path)

    log.info("Sleep 5 to allow procecsses to finish")
    time.sleep(5)
    log.info("Cleanup %s" % script_path)
    _common.remove_file(script_path)
