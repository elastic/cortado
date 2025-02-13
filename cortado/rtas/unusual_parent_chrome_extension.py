# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="9e31b8ae-c0a6-46c9-9634-d1aebceea541",
    name="unusual_parent_chrome_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="d7fda3d7-fe77-49c2-8b50-d28a6da206c4", name="Chromium Extension Loaded from Unusual Parent")
    ],
    techniques=["T1176"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    proc = "C:\\Users\\Public\\proc.exe"
    childproc = "C:\\Users\\Public\\childproc.exe"
    _common.copy_file(EXE_FILE, proc)
    _common.copy_file(EXE_FILE, childproc)

    _ = _common.execute_command([proc, "/c", "echo", f"--load-extension; & {childproc}"], timeout_secs=5)
    _common.remove_files([childproc, proc])
