# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path
from . import _common


@register_code_rta(
    id="72c2470b-c96e-4b44-88ec-1a67c4ec091c",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        {
            "rule_name": "Potential Persistence via Atom Init Script Modification",
            "rule_id": "b4449455-f986-4b5a-82ed-e36b129331f7",
        }
    ],
    techniques=["T1037"],
)
def main():
    atom_dir = Path.home().joinpath(".atom")
    atom_dir.mkdir(parents=True, exist_ok=True)
    atom_path = atom_dir.joinpath("init.coffee")
    _common.log(f"Executing file modification on {atom_path} to mimic malicious Atom init file.")
    _common.temporary_file_helper("testing", file_name=atom_path)

    # cleanup
    _common.remove_directory(str(atom_dir))


