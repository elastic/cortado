# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="4b2e6004-6685-4a0f-b483-efc84dfb2393",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {"rule_id": "8dd7588d-fc28-40c0-adfb-14789c763984", "rule_name": "Suspicious Windows Command Shell Execution"}
    ],
    siem_rules=[],
    techniques=[""],
)
def main():
    cmd = "C:\\Windows\\System32\\cmd.exe"
    _common.execute([cmd, "/C", "echo", "wscript"], timeout=5, kill=True)


if __name__ == "__main__":
    exit(main())
