# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="ad0986cb-b5ef-41ad-9b40-8d708dc28844",
    platforms=["windows"],
    endpoint_rules=[
        {
        'rule_id': 'a5416b1f-fc3f-4162-936d-34086689c3b0',
        'rule_name': 'DLL Execution via Visual Studio Live Share'
        }
    ],
    siem_rules=[],
    techniques=['T1218'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")


@_common.requires_os(*metadata.platforms)
def main():
    vslsagent = "C:\\Users\\Public\\vsls-agent.exe"
    _common.copy_file(EXE_FILE, vslsagent)

    _common.execute([vslsagent, "/c", "echo", "--agentExtensionPath"], timeout=5, kill=True)
    _common.remove_files(vslsagent)


if __name__ == "__main__":
    exit(main())
