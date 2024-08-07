# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="5c520396-4951-4763-8512-a53545bcff9c",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_name": "Linux Shared Object Load via SSH-Keygen", "rule_id": "cc29bf55-8d7f-45df-b8fe-212968c8951c"}
    ],
    techniques=["T1574"],
)
def main():
    masquerade = "/tmp/ssh-keygen"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "-D", "foo"]

    # Execute command
    _common.log("Launching fake command to simulate ssh-keygen shared object load")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


