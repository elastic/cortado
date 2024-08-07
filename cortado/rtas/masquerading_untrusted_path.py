# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="aef45f58-14c8-4934-8518-62a254d96b77",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        {"rule_id": "e216abf2-1961-43fb-bef2-0c4b34c78600", "rule_name": "Linux Binary Masquerading via Untrusted Path"}
    ],
    siem_rules=[],
    techniques=["T1036", "T1036.004"],
)
def main():
    masquerade = "/tmp/apt"
    source = _common.get_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    _common.log("Launching fake builtin commands for Linux Binary Masquerading via Untrusted Path")
    command = "install"
    _common.execute([masquerade, command], timeout=10, kill=True, shell=True)
    # cleanup
    _common.remove_file(masquerade)


