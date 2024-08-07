# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="469c7bb5-44e2-4a85-b14d-5aee4f2b18c1",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="0524c24c-e45e-4220-b21a-abdba0c46c4d", name="Regsvr32 Scriptlet Execution"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5db08297-bf72-49f4-b426-f405c2b01326", name="Regsvr32 with Unusual Arguments"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    regsvr32 = "C:\\Users\\Public\\regsvr32.exe"
    _common.copy_file(EXE_FILE, regsvr32)

    _common.execute([regsvr32, "/c", "echo", "scrobj.exe /i:"], timeout=10)
    _common.remove_files(regsvr32)


if __name__ == "__main__":
    exit(main())
