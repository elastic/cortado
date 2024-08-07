# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path


@register_code_rta(
    id="858475a2-78a6-40f8-8691-7ce0c631cc0c",
    name="file_ms_template_macros",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="608eae71-6797-4ded-bfaa-41bcb17a8498", name="Office Application Startup via Template File Modification"
        )
    ],
    siem_rules=[],
    techniques=["T1137", "T1137.001"],
)
def main():
    path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Templates\\"
    Path(path).mkdir(parents=True, exist_ok=True)
    file = path + "\\Normal.dotm"

    _common.temporary_file_helper("testing", file_name=file)
