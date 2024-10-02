# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="74d0c16a-8af1-4dbb-9202-cc4b25208ea6",
    name="double_persist",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="392b0c89-1427-4601-8b32-01e8e40600a6",
            name="Untrusted Process Writing to Commonly Abused Persistence Locations",
        )
    ],
    techniques=["T1547", "T1112"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/DoublePersist.exe")

    binary = "DoublePersist.exe"
    _common.copy_file(EXE_FILE, binary)

    _ = _common.execute_command([binary])
    _common.remove_files([binary])
