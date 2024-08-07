# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="163dbe60-28e0-4042-b2f0-173dddea877b",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_name": "Linux init (PID 1) Secret Dump via GDB", "rule_id": "ba70be59-bf50-48a9-8b36-0f0808a50fb8"}
    ],
    siem_rules=[
        {"rule_name": "Linux init (PID 1) Secret Dump via GDB", "rule_id": "d4ff2f53-c802-4d2e-9fb9-9ecc08356c3f"}
    ],
    techniques=["T1003"],
)
def main():
    masquerade = "/tmp/gdb"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake GDB commands to hook the init process")
    _common.execute([masquerade, "--pid", "1"], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


