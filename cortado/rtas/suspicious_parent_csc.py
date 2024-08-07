# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="07eaba7d-c0ff-4480-87cf-5ad39805dc92",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="201200f1-a99b-43fb-88ed-f65a45c4972c", name="Suspicious .NET Code Compilation")],
    techniques=["T1027", "T1027.004"],
)
def main():
    EXE_FILE = _common.get_path("bin", "renamed_posh.exe")

    wscript = "C:\\Users\\Public\\wscript.exe"
    csc = "C:\\Users\\Public\\csc.exe"
    _common.copy_file(EXE_FILE, wscript)
    _common.copy_file(EXE_FILE, csc)

    # Execute command
    _common.execute([wscript, "/c", csc], timeout=2, kill=True)
    _common.remove_files(wscript, csc)
