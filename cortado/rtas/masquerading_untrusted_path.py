# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="aef45f58-14c8-4934-8518-62a254d96b77",
    name="masquerading_untrusted_path",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="e216abf2-1961-43fb-bef2-0c4b34c78600", name="Linux Binary Masquerading via Untrusted Path")
    ],
    siem_rules=[],
    techniques=["T1036", "T1036.004"],
)
def main():
    masquerade = "/tmp/apt"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake builtin commands for Linux Binary Masquerading via Untrusted Path")
    command = "install"
    _ = _common.execute_command([masquerade, command], timeout_secs=10, kill=True, shell=True)
    # cleanup
    _common.remove_file(masquerade)
