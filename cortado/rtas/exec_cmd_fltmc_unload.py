# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="fc1e40b8-ae2d-4479-a854-77b346982894",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{'rule_id': '06dceabf-adca-48af-ac79-ffdf4c3b1e9a', 'rule_name': 'Potential Evasion via Filter Manager'}],
    techniques=['T1562', 'T1562.001'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    fltmc = "C:\\Users\\Public\\fltmc.exe"
    _common.copy_file(EXE_FILE, fltmc)

    # Execute command
    _common.execute([fltmc, "/c", "echo", "unload"], timeout=10)
    _common.remove_file(fltmc)


if __name__ == "__main__":
    exit(main())
