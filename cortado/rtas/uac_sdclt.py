# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="7d1ca1a2-be0e-4cd8-944f-2da2fc625468",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="e9095298-65e0-40a2-97c9-055de8685645", name="UAC Bypass via Sdclt"),
    ],
    siem_rules=[],
    techniques=["T1548", "T1036"],
)

EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    sdclt = "C:\\Users\\Public\\sdclt.exe"
    _common.copy_file(EXE_FILE, sdclt)

    _common.execute([sdclt, "/c", "echo", "/kickoffelev; powershell"], timeout=2, kill=True)
    _common.remove_files(sdclt)


if __name__ == "__main__":
    exit(main())
