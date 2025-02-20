# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="b12372b8-0e76-4b3d-9dfc-880664893eb9",
    name="exec_susp_parent_child",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="18a26e3e-e535-4d23-8ffa-a3cdba56d16e", name="Suspicious Parent-Child Relationship")
    ],
    techniques=["T1055", "T1036"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    posh = "C:\\Users\\Public\\posh.exe"
    tiworker = "C:\\Users\\Public\\TiWorker.exe"
    _common.copy_file(EXE_FILE, posh)
    _common.copy_file(EXE_FILE, tiworker)

    # Execute command
    _ = _common.execute_command([posh, "/c", tiworker], timeout_secs=3)
    _common.remove_files([posh, tiworker])
