# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="469d383a-d03f-470a-bcba-15da9dd373ed",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(id="5db08297-bf72-49f4-b426-f405c2b01326", name="Regsvr32 with Unusual Arguments"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)

EXE_FILE = _common.get_path("bin", "renamed.exe")



def main():
    binary = "regsvr32.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute Command
    _common.execute([binary, "cd", "C:\\Users\\Public\\"], timeout=10, kill=True)

    _common.remove_file(binary)


if __name__ == "__main__":
    exit(main())
