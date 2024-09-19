# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="2e5d3ddd-6dc4-4ebf-93e3-c32698b8df40",
    name="file_create_task_file",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="1327384f-00f3-44d5-9a8c-2373ba071e92", name="Persistence via Scheduled Job Creation")],
    techniques=["T1053", "T1053.005"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    path = "C:\\Windows\\Tasks\\a.job"
    _common.copy_file(EXE_FILE, path)
    _common.remove_files([path])
