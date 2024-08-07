# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="374718be-d841-4381-a75f-ef54f0d5eb18",
    name="credential_access_known_utilities",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="3c44fc50-2672-48b3-af77-ff43b895ac70", name="Credential Access via Known Utilities")
    ],
    siem_rules=[],
    techniques=["T1003"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed.exe")

    binary = "ProcessDump.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute command
    _common.execute([binary], timeout=5, kill=True)

    _common.remove_files(binary)
