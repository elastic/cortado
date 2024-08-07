# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="fa1dd615-73f0-46d0-b047-b495337d356b",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="d461fac0-43e8-49e2-85ea-3a58fe120b4f", name="Shell Execution via Apple Scripting")],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/osascript"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake osascript commands to mimic sh execution")
    _common.execute([masquerade, "childprocess", "sh -c 'ls'"], shell=True, timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
