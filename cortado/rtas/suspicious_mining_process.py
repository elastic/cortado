# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="425ba45e-10eb-4067-93f4-95701d26da3d",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_id": "fbf9342e-3d1e-4fba-a828-92fa0fb4d21b", "rule_name": "Suspicious Mining Process Events"}
    ],
    siem_rules=[],
    techniques=["T1059", "T1059.004"],
)
def main():
    masquerade = "/tmp/systemctl"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake builtin commands for disabling _common mining services by name")
    command = "start"
    command1 = "apache4.service"
    _common.execute([masquerade, command, command1], timeout=10, kill=True, shell=True)
    # cleanup
    _common.remove_file(masquerade)


