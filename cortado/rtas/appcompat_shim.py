# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Application Compatibility Shims
# RTA: appcompat_shim.py
# ATT&CK: T1138
# Description: Use sdbinst.exe to install a binary patch/application shim.

import time

from . import _common, RuleMetadata, register_code_rta, OSType


SHIM_FILE = "bin/CVE-2013-3893.sdb"


@register_code_rta(
    id="a4a8608e-d94f-4eb1-b500-738328307bbc",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="fd4a992d-6130-4802-9ff8-829b89ae801f", name="Potential Application Shimming via Sdbinst")
    ],
    techniques=["T1546"],
    ancillary_files=[SHIM_FILE],
)
def main():
    _common.log("Application Compatibility Shims")

    _common.execute(["sdbinst.exe", "-q", "-p", SHIM_FILE])
    time.sleep(2)

    _common.log("Removing installed shim", log_type="-")
    _common.execute(["sdbinst.exe", "-u", SHIM_FILE])
