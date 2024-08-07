# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="219dee0a-48ad-4e17-ab59-783a619a7bd5",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{'rule_id': 'c6453e73-90eb-4fe7-a98c-cde7bbfc504a', 'rule_name': 'Remote File Download via MpCmdRun'}],
    techniques=['T1105'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    mpcmdrun = "C:\\Users\\Public\\MpCmdRun.exe"
    _common.copy_file(EXE_FILE, mpcmdrun)

    # Execute command
    _common.execute([mpcmdrun, "/c", "echo", "-DownloadFIle", "-Url", "-path"], timeout=10)
    _common.remove_file(mpcmdrun)


