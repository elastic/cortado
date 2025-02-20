# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Network Traffic from InstallUtil
# RTA: installutil_network.py
# ATT&CK: T1118
# Elastic detection: InstallUtil Process Making Network Connections
# Elastic detection: Unusual Network Activity from a Windows System Binary
# Description: Uses mock .NET malware and InstallUtil to create network activity from InstallUtil.

import logging
import sys
from pathlib import Path

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

MY_DOT_NET_EXE = "bin/mydotnet.exe"


@register_code_rta(
    id="6dfa88c9-9fb2-4fb0-8bea-0bc45222b498",
    name="installutil_network",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="a13167f1-eec2-4015-9631-1fee60406dcf", name="InstallUtil Process Making Network Connections"),
        RuleMetadata(
            id="1fe3b299-fbb5-4657-a937-1d746f2c711a", name="Unusual Network Activity from a Windows System Binary"
        ),
    ],
    techniques=["T1127", "T1218"],
    ancillary_files=[MY_DOT_NET_EXE],
)
def main():
    server, _, port = _common.serve_dir_over_http()
    _common.clear_web_cache()

    target_app = Path("mydotnet.exe")
    _common.patch_file_with_bytes(
        _common.get_resource_path(MY_DOT_NET_EXE),
        _common.as_wchar(":8000"),
        _common.as_wchar(":%d" % port),
        target_file=target_app,
    )

    install_util64 = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe"
    install_util86 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe"

    install_util = None
    if Path(install_util64).is_file():
        install_util = install_util64
    elif Path(install_util86).is_file():
        install_util = install_util86

    if install_util:
        _common.clear_web_cache()
        _ = _common.execute_command([install_util, "/logfile=", "/LogToConsole=False", "/U", target_app])

    else:
        log.info("Unable to find InstallUtil, creating temp file")
        install_util = Path("InstallUtil.exe").resolve()
        _common.copy_file(sys.executable, install_util)
        _ = _common.execute_command(
            [
                install_util,
                "-c",
                "import urllib; urllib.urlopen('http://%s:%d')" % (_common.get_host_ip(), port),
            ]
        )
        _common.remove_file(install_util)

    _common.remove_file(target_app)
    server.shutdown()
