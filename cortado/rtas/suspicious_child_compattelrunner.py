# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common



@register_code_rta(
    id="82e913eb-441b-4c93-bad9-6340af0cc71b",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[{
        'rule_id': '68921d85-d0dc-48b3-865f-43291ca2c4f2',
        'rule_name': 'Persistence via TelemetryController Scheduled Task Hijack'
    }],
    techniques=['T1053', 'T1053.005'],
)
EXE_FILE = _common.get_path("bin", "renamed_posh.exe")



def main():
    compattelrunner = "C:\\Users\\Public\\compattelrunner.exe"
    child = "C:\\Users\\Public\\child.exe"
    _common.copy_file(EXE_FILE, child)
    _common.copy_file(EXE_FILE, compattelrunner)

    _common.execute([compattelrunner, "/c", child, "echo", "-cv"], timeout=5, kill=True)
    _common.remove_files(child, compattelrunner)


