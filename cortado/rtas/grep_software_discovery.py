# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType


@register_code_rta(
    id="6ef908be-9ed3-413d-8d4d-94446107eecc",
    name="grep_software_discovery",
    platforms=["macos", "linux"],
    endpoint_rules=[
        RuleMetadata(id="13eade2e-73dd-4fab-a511-88258635559d", name="Potential Security Software Discovery via Grep")
    ],
    siem_rules=[RuleMetadata(id="870aecc0-cea4-4110-af3f-e02e9b373655", name="Security Software Discovery via Grep")],
    techniques=["T1518"],
)
def main():
    masquerade = "/tmp/grep"
    if _common.CURRENT_OS == "linux":
        source = _common.get_path("bin", "linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
    else:
        _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake grep commands to discover software")
    _common.execute([masquerade, "testgreptestLittle Snitchtest"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
