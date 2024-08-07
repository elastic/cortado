# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="fafdfbda-add8-40a1-b2b5-640fce12413e",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        {"rule_id": "d117cbb4-7d56-41b4-b999-bdf8c25648a0", "rule_name": "Symbolic Link to Shadow Copy Created"}
    ],
    techniques=["T1003"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

    # Execute command
    _common.execute([powershell, "/c", "echo", "mklink", "HarddiskVolumeShadowCopy"], timeout=10)


if __name__ == "__main__":
    exit(main())
