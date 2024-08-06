# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="af989d34-49af-4815-8d58-ab10835bfc35",
    platforms=["windows"],
    endpoint_rules=[{'rule_id': 'ccfca0c7-c975-4735-82bd-954ffbafd00b', 'rule_name': 'Evasion via Double File Extension'}],
    siem_rules=[],
    techniques=[""],
)


@_common.requires_os(*metadata.platforms)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    doubleext = "C:\\Users\\Public\\powershell.pdf.exe"
    _common.copy_file(powershell, doubleext)

    _common.execute([doubleext], timeout=1, kill=True)
    _common.remove_file(doubleext)


if __name__ == "__main__":
    exit(main())
