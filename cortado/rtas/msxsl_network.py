# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: msxsl.exe Network
# RTA: msxsl_network.py
# ATT&CK: T1127
# Description: Generates network traffic from msxsl.exe

import logging

from . import OSType, RuleMetadata, _common, register_code_rta, _const

log = logging.getLogger(__name__)


MS_XSL_EXE = "bin/msxsl.exe"
XML_FILE = "bin/customers.xml"
XSL_FILE = "bin/cscript.xsl"


@register_code_rta(
    id="a8331ff5-2199-48cf-9284-88351c859835",
    name="msxsl_network",
    platforms=[OSType.WINDOWS],
    siem_rules=[RuleMetadata(id="b86afe07-0d98-4738-b15d-8d7465f95ff5", name="Network Connection via MsXsl")],
    techniques=["T1220"],
    ancillary_files=[MS_XSL_EXE, XML_FILE, XSL_FILE],
)
def main():
    log.info("MsXsl Beacon")
    server, ip, port = _common.serve_dir_over_http()
    _common.clear_web_cache()

    new_callback = "http://%s:%d" % (ip, port)
    log.info("Updating the callback to %s" % new_callback)
    _common.patch_file_with_regex(XSL_FILE, _const.CALLBACK_REGEX, new_callback)

    _ = _common.execute_command([MS_XSL_EXE, XML_FILE, XSL_FILE])
    server.shutdown()
