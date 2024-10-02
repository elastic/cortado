# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious DLL Registration by Regsvr32
# RTA: suspicious_dll_registration_regsvr32.py
# ATT&CK: T1117
# Description: Pretends to register DLL without traditional DLL extension using RegSvr32

import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="cda5b0b4-5b9c-4285-8adc-f89b375e5485",
    name="suspicious_dll_registration_regsvr32",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    techniques=[],
)
def main():
    log.info("Suspicious DLL Registration by Regsvr32")

    _ = _common.execute_command(["regsvr32.exe", "-s", "meow.txt"])
