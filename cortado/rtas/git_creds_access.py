# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from pathlib import Path


@register_code_rta(
    id="e15ea2ec-c8a9-4203-8d01-d18d1c27fd58",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="39f60a36-8c5a-4703-8576-ad3e8c800a0f", name="Sensitive File Access - Cloud Credentials")
    ],
    siem_rules=[],
    techniques=["T1552"],
)
def main():
    powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    gitpath = "C:\\Users\\Public\\.config\\git"

    try:
        Path(gitpath).mkdir(parents=True)
    except Exception:
        pass
    gitcreds = gitpath + "\\credentials"
    cmd = f"echo 'aaaaaa' > {gitcreds}; cat {gitcreds}"
    # Execute command
    _common.execute([powershell, "/c", cmd], timeout=10)
    _common.remove_file(gitcreds)
