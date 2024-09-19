# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="82e913eb-441b-4c93-bad9-6340af0cc71b",
    name="suspicious_child_compattelrunner",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="68921d85-d0dc-48b3-865f-43291ca2c4f2", name="Persistence via TelemetryController Scheduled Task Hijack"
        )
    ],
    techniques=["T1053", "T1053.005"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    compattelrunner = "C:\\Users\\Public\\compattelrunner.exe"
    child = "C:\\Users\\Public\\child.exe"
    _common.copy_file(EXE_FILE, child)
    _common.copy_file(EXE_FILE, compattelrunner)

    _ = _common.execute_command([compattelrunner, "/c", child, "echo", "-cv"], timeout_secs=5)
    _common.remove_files([child, compattelrunner])
