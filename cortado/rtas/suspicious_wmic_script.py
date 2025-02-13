# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Suspicious WMIC script execution
# RTA: suspicious_wmic_script.py
# Description: Uses the WMI command-line utility to execute built-in Windows commands which are unusual or unexpected.
# Reference: https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html

import logging
import os

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


xsl_file = "test.xsl"
xsl_content = """<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("ipconfig.exe");
    ]]> </ms:script>
</stylesheet>
"""


@register_code_rta(
    id="16b3d9c6-e188-49c5-8dce-d3eb5b0fcf91",
    name="suspicious_wmic_script",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="7f370d54-c0eb-4270-ac5a-9a6020585dc6", name="Suspicious WMIC XSL Script Execution")],
    techniques=["T1220"],
)
def main():
    log.info("Executing suspicious WMIC script")

    with open(xsl_file, "w") as f:
        _ = f.write(xsl_content)

    # Many variations on this command. For example, -format:, /  format : , etc
    _ = _common.execute_command(["wmic.exe", "os", "get", "/format:" + xsl_file])

    os.remove(xsl_file)
