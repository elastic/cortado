# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="0860c487-e9e0-4f86-9829-5bb98f615046",
    name="exec_unusual_directory",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="16c84e67-e5e7-44ff-aefa-4d771bcafc0c", name="Execution from Unusual Directory"),
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
    ],
    techniques=["T1218", "T1036", "T1059"],
)
def main():
    exe_path = "c:\\windows\\system32\\cscript.exe"
    binary = "c:\\Users\\Public\\cscript.exe"
    _common.copy_file(exe_path, binary)

    # Execute command
    log.info("Executing cscript from unusual directory")
    _ = _common.execute_command(binary, shell=True, timeout_secs=5)

    _common.remove_files([binary])
