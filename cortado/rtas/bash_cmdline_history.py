# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="631a211d-bdaa-4b9d-a786-31d84d7bc070",
    name="bash_cmdline_history",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="31da6564-b3d3-4fc8-9a96-75ad0b364363", name="Tampering of Bash Command-Line History")
    ],
    techniques=["T1070", "T1070.003"],
)
def main():
    masquerade = "/tmp/history"
    source = _common.get_resource_path("bin/linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)

    # Execute command
    log.info("Launching fake builtin commands for tampering of bash command line history")
    command = "-c"
    _ = _common.execute_command([masquerade, command], timeout_secs=10)
    # cleanup
    _common.remove_file(masquerade)
