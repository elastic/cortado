# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="af989d34-49af-4815-8d58-ab10835bfc35",
    name="file_double_extension",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[RuleMetadata(id="ccfca0c7-c975-4735-82bd-954ffbafd00b", name="Evasion via Double File Extension")],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    doubleext = "C:\\Users\\Public\\powershell.pdf.exe"
    _common.copy_file(powershell, doubleext)

    _ = _common.execute_command(doubleext, shell=True, timeout_secs=1)
    _common.remove_file(doubleext)
