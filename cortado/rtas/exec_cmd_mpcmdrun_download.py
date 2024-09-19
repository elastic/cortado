# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="219dee0a-48ad-4e17-ab59-783a619a7bd5",
    name="exec_cmd_mpcmdrun_download",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="c6453e73-90eb-4fe7-a98c-cde7bbfc504a", name="Remote File Download via MpCmdRun")],
    techniques=["T1105"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    mpcmdrun = "C:\\Users\\Public\\MpCmdRun.exe"
    _common.copy_file(EXE_FILE, mpcmdrun)

    # Execute command
    _ = _common.execute_command([mpcmdrun, "/c", "echo", "-DownloadFIle", "-Url", "-path"], timeout_secs=10)
    _common.remove_file(mpcmdrun)
