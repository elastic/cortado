# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="0860c487-e9e0-4f86-9829-5bb98f615046",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    exe_path = "c:\\windows\\system32\\cscript.exe"
    binary = "c:\\Users\\Public\\cscript.exe"
    _common.copy_file(exe_path, binary)

    # Execute command
    _common.log("Executing cscript from unusual directory")
    _common.execute([binary], timeout=5, kill=True)

    _common.remove_files(binary)


if __name__ == "__main__":
    exit(main())
