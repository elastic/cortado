# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="c798f63a-f8be-459a-bb75-407e97f55faa",
    name="suspicious_office_child",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="c34a9dca-66cf-4283-944d-1800b28ae690", name="Suspicious Microsoft Office Child Process")
    ],
    siem_rules=[],
    techniques=["T1566"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed.exe")

    binary = "winword.exe"
    _common.copy_file(EXE_FILE, binary)

    # Execute command
    _common.execute([binary, "/c", "certutil.exe"], timeout=5, kill=True)

    _common.remove_files(binary)
