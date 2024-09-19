# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5370760b-09ea-4258-bcfa-e426726a4777",
    name="file_exe_ususual_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="b0207677-5041-470b-981d-13ab956cf5b4", name="Execution via Renamed Signed Binary Proxy"),
        RuleMetadata(id="d1b6319f-2933-4872-8e67-5728fd09a4a1", name="Executable with Unusual Filename"),
        RuleMetadata(id="6daf97b0-8e29-476b-998a-c3d168d98506", name="Process Execution with Unusual File Extension"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    unusualext = "C:\\Users\\Public\\powershell.exe.pdf"
    _common.copy_file(powershell, unusualext)

    _ = _common.execute_command([unusualext], timeout_secs=1)
    _common.remove_file(unusualext)
