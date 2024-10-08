# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8c77b44c-fb6d-4082-b62d-147918c622d9",
    name="network_connection_process_unusual_args",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="35dedf0c-8db6-4d70-b2dc-a133b808211f", name="Binary Masquerading via Untrusted Path"),
        RuleMetadata(
            id="95601d8b-b969-4189-9744-090140ae29e6", name="Network Connection via Process with Unusual Arguments"
        ),
    ],
    techniques=["T1055", "T1036"],
)
def main():
    exe_file = _common.get_resource_path("bin/regsvr32.exe")

    log.info("Making connection using fake regsvr32.exe")
    _ = _common.execute_command(str(exe_file), shell=True, timeout_secs=10)
