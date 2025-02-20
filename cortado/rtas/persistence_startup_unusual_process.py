# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9a0c0715-5225-4170-a505-0e3cc4dfd63e",
    name="persistence_startup_unusual_process",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
        RuleMetadata(
            id="30a90136-7831-41c3-a2aa-1a303c1186ac", name="Unusual File Written or Modified in Startup Folder"
        ),
        RuleMetadata(id="95d13ce1-ffb2-4be8-a56e-cc9a891e81e2", name="Startup Persistence via Unusual Process"),
        RuleMetadata(
            id="be42f9fc-bdca-41cd-b125-f223d09eef69",
            name="Script Interpreter Process Writing to Commonly Abused Persistence Locations",
        ),
        RuleMetadata(
            id="a85000c8-3eac-413b-8353-079343c2b6f0", name="Startup Persistence via Windows Script Interpreter"
        ),
    ],
    techniques=["T1547", "T1218", "T1036", "T1059"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    tempowershell = "C:\\Windows\\notp0sh.exe"
    posh = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\posh.exe"
    _common.copy_file(powershell, tempowershell)

    time.sleep(2)
    _ = _common.execute_command([tempowershell, "-c", "Copy-Item", powershell, tempowershell])
    _common.remove_files([tempowershell, posh])
