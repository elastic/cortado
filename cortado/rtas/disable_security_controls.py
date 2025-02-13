# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="4eceac28-10c3-425f-a007-c03a9b57956f",
    name="disable_security_controls",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="b63df89d-ac6f-44d7-80fa-ddf038295e42", name="Attempt to Disable Linux Security and Logging Controls"
        ),
    ],
    techniques=["T1562", "T1562.001"],
)
def main() -> None:
    masquerade = "/tmp/systemctl"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake builtin commands for disabling security controls")
    command = "stop"
    command1 = "apparmor"
    _ = _common.execute_command([masquerade, command, command1], timeout_secs=10)  # noqa: S604
    # cleanup
    _common.remove_file(masquerade)
