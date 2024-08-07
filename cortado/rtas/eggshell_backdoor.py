# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="be090f8e-dc7b-41eb-9c7e-74a0aed0dad1",
    platforms=["macos", "linux"],
    endpoint_rules=[RuleMetadata(id="feed7842-34a6-4764-b858-6e5ac01a5ab7", name="EggShell Backdoor Execution")],
    siem_rules=[RuleMetadata(id="41824afb-d68c-4d0e-bfee-474dac1fa56e", name="EggShell Backdoor Execution")],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/eggshell"
    if _common.CURRENT_OS == "linux":
        source = _common.get_path("bin", "linux.ditto_and_spawn")
        _common.copy_file(source, masquerade)
    else:
        _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake commands for EggShell backdoor behavior")
    _common.execute([masquerade, "eyJkZWJ1ZyI6test"], timeout=10, kill=True)

    # cleanup
    _common.remove_file(masquerade)
