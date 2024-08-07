# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path


@register_code_rta(
    id="a6c80b08-ca72-4c3e-93c7-ac3421e4235e",
    name="file_delete_vbk",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="11ea6bec-ebde-4d71-a8e9-784948f8e3e9", name="Third-party Backup Files Deleted via Unexpected Process"
        )
    ],
    techniques=["T1490"],
)
def main():
    fakebkp = Path("fake.vbk").resolve()
    with open(fakebkp, "w"):
        pass
    _common.remove_file(fakebkp)
