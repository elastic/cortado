# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import pathlib

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="5fce12c8-642a-49ad-9a94-e21d23149afb",
    name="suspicious_kibana_child",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(id="0b206183-7f90-461d-80b3-8a147147ae78", name="Suspicious Kibana Child Process"),
    ],
    techniques=["T1190", "T1059", "T1059.004"],
)
def main() -> None:
    masquerade = "/tmp/kibana/node/bin/node"
    executable_dir = "/tmp/kibana/node/bin/"
    pathlib.Path(executable_dir).mkdir(parents=True, exist_ok=True)
    masquerade2 = "/tmp/bash"
    # Using the Linux binary that simulates parent-> child process in Linux
    source = _common.get_resource_path("bin/linux_ditto_and_spawn_parent_child")
    _common.copy_file(source, masquerade)
    _common.copy_file(source, masquerade2)

    # Execute command
    log.info("Executing Fake Commands to simulate Shell Command Execution via Kworker")
    command = (
        f"{masquerade2} /bin/sh -c lsb_release -a , "
        f"/bin/sh -c git rev-parse --short HEAD echo --unhandled-rejections=warn"
    )
    _ = _common.execute_command([masquerade, "childprocess", command], timeout_secs=10)  # noqa: S604

    # cleanup
    _common.remove_file(masquerade)
