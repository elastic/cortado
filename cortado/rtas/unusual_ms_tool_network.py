# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Unexpected Network Activity from Microsoft Tools
# RTA: unusual_ms_tool_network.py
# ATT&CK: T1127
# Description: Creates network traffic from a process which is named to match _common administration and developer tools
#              that do not typically make network traffic unless being used maliciously.

import logging
import shutil
import sys

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


urlliblib = "urllib.request"

process_names = [
    "bginfo.exe",
    "msdt.exe",
    "ieexec.exe",
    "cdb.exe",
    "dnx.exe",
    "rcsi.exe",
    "csi.exe",
    "cmstp.exe",
    "xwizard.exe",
    "fsi.exe",
    "odbcconf.exe",
]


def http_from_process(name: str, ip: str, port: int):
    current_dir = _common.get_current_dir()
    path = current_dir / name
    log.info("Making HTTP GET from %s" % path)
    shutil.copy(sys.executable, path)
    _ = _common.execute_command(
        [
            str(path),
            "-c",
            "from %s import urlopen ; urlopen('http://%s:%d')" % (urlliblib, ip, port),
        ]
    )
    _common.remove_file(path)


@register_code_rta(
    id="cf94f5cc-5265-4287-80e5-82d9663ecf2e",
    name="unusual_ms_tool_network",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1fe3b299-fbb5-4657-a937-1d746f2c711a", name="Unusual Network Activity from a Windows System Binary"
        ),
        RuleMetadata(id="610949a1-312f-4e04-bb55-3a79b8c95267", name="Unusual Process Network Connection"),
    ],
    techniques=["T1127"],
)
def main():
    server, ip, port = _common.serve_dir_over_http()

    for process in process_names:
        http_from_process(process, ip, port)

    server.shutdown()
