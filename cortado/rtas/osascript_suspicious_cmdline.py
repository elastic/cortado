# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="af8d27bb-1673-463f-8631-a5b30278cf33",
    name="osascript_suspicious_cmdline",
    platforms=[OSType.MACOS],
    endpoint_rules=[RuleMetadata(id="7b9d544a-5b2a-4f0d-984a-cdc89a7fad25", name="Suspicious Apple Script Execution")],
    siem_rules=[],
    techniques=["T1105", "T1059"],
)
def main():
    masquerade = "/tmp/osascript"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake osascript and javascript commands")
    _common.execute(
        [masquerade, "JavaScript", "eval('curl http://www.test')"],
        timeout=10,
        kill=True,
    )

    # cleanup
    _common.remove_file(masquerade)
