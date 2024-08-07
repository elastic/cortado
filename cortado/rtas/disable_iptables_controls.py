# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="2b07eb19-c71e-4e79-b0b6-a3850bdbf273",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="02db53f7-d6de-4e69-8e05-819233583c87", name="Attempt to Disable IPTables or Firewall")
    ],
    siem_rules=[],
    techniques=["T1562", "T1562.001"],
)
def main():
    masquerade = "/tmp/ufw"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake builtin commands for disabling iptables")
    command = "disable"
    _common.execute([masquerade, command], timeout=10, kill=True, shell=True)
    # cleanup
    _common.remove_file(masquerade)
