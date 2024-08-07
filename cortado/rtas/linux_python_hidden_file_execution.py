# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="d2c9baa4-6dda-46ff-acaa-f70ac0d3391b",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="b25ec4e7-34f1-40c2-b683-bbf1dcdd84e5", name="Linux Hidden Folder or File Execution via Python")
    ],
    techniques=["T1059"],
)
def main():
    masquerade = "/tmp/python"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    commands = [masquerade, "python", "/dev/shm/.foo"]

    # Execute command
    _common.log("Launching fake command to simulate Python hidden execution")
    _common.execute([*commands], timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)
