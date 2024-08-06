# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import subprocess
from pathlib import Path
from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="e7a55d39-37b4-4f37-9519-3779b3c23bfa",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="676ac66c-4899-498f-ae21-ed5620af5477", name="Suspicious Bitsadmin Activity"),
        RuleMetadata(id="c34a9dca-66cf-4283-944d-1800b28ae690", name="Suspicious Microsoft Office Child Process"),
    ],
    siem_rules=[],
    techniques=["T1197", "T1566"],
)

ROOT_DIR = Path(__file__).parent
EXE_FILE = _common.get_path("bin", "renamed.exe")


@_common.requires_os(*metadata.platforms)
def main():

    fake_word = ROOT_DIR / "winword.exe"
    _common.log(f"Copying {EXE_FILE} to {fake_word}")
    _common.copy_file(EXE_FILE, fake_word)

    command = subprocess.list2cmdline(["bitsadmin.exe", "/Transfer", "/Download"])
    _common.execute([fake_word, "/c", command], timeout=15, kill=True)
    _common.execute(["taskkill", "/f", "/im", "bitsadmin.exe"])

    _common.remove_files(fake_word)


if __name__ == "__main__":
    exit(main())
