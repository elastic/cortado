# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import subprocess
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="e7a55d39-37b4-4f37-9519-3779b3c23bfa",
    name="bitsadmin_execution",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="676ac66c-4899-498f-ae21-ed5620af5477", name="Suspicious Bitsadmin Activity"),
        RuleMetadata(id="c34a9dca-66cf-4283-944d-1800b28ae690", name="Suspicious Microsoft Office Child Process"),
    ],
    siem_rules=[],
    techniques=["T1197", "T1566"],
)
def main():
    # FIXME
    ROOT_DIR = Path(__file__).parent
    EXE_FILE = _common.get_resource_path("bin/renamed.exe")

    fake_word = ROOT_DIR / "winword.exe"
    log.info(f"Copying {EXE_FILE} to {fake_word}")
    _common.copy_file(EXE_FILE, fake_word)

    command = subprocess.list2cmdline(["bitsadmin.exe", "/Transfer", "/Download"])
    _ = _common.execute_command([fake_word, "/c", command], timeout_secs=15)
    _ = _common.execute_command(["taskkill", "/f", "/im", "bitsadmin.exe"])

    _common.remove_files([fake_word])
