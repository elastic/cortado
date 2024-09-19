# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Hosts File Modified
# RTA: hosts_file_modify.py
# ATT&CK: T1492
# Description: Modifies the hosts file

import logging
import os
import random
import time
from pathlib import Path
from string import ascii_letters

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="f24491d0-720b-4150-a2a1-45b5b07238aa",
    name="hosts_file_modify",
    platforms=[OSType.WINDOWS, OSType.LINUX, OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="9c260313-c811-4ec8-ab89-8f6530e0246c", name="Hosts File Modified")],
    techniques=["T1565"],
)
def main():
    hosts_files = {
        OSType.WINDOWS: "C:\\Windows\\system32\\drivers\\etc\\hosts",
        OSType.LINUX: "/etc/hosts",
        OSType.MACOS: "/private/etc/hosts",
    }
    current_os = _common.get_current_os()
    hosts_file = hosts_files[current_os]

    backup = Path(hosts_file + "_backup").resolve()
    log.info("Backing up original 'hosts' file.")
    _common.copy_file(hosts_file, backup)

    # add randomness for diffs for FIM module
    randomness = "".join(random.sample(ascii_letters, 10))
    entry = [
        "",
        "# RTA hosts_modify was here",
        "# 8.8.8.8 https://www.{random}.google.com".format(random=randomness),
    ]
    with open(hosts_file, "a") as f:
        _ = f.write("\n".join(entry))

    log.info("Updated hosts file")
    with open(hosts_file, "r") as f:
        log.info(f.read())

    time.sleep(2)

    # cleanup
    log.info("Restoring hosts from backup copy.")
    _common.copy_file(backup, hosts_file)
    os.remove(backup)
