# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: msxsl.exe Network
# RTA: msxsl_network.py
# ATT&CK: T1127
# Description: Generates network traffic from msxsl.exe

from . import _common



@register_code_rta(
    id="a8331ff5-2199-48cf-9284-88351c859835",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="b86afe07-0d98-4738-b15d-8d7465f95ff5", name="Network Connection via MsXsl")],
    techniques=["T1220"],
)


MS_XSL = _common.get_path("bin", "msxsl.exe")
XML_FILE = _common.get_path("bin", "customers.xml")
XSL_FILE = _common.get_path("bin", "cscript.xsl")



@_common.dependencies(MS_XSL, XML_FILE, XSL_FILE)
def main():
    _common.log("MsXsl Beacon")
    server, ip, port = _common.serve_web()
    _common.clear_web_cache()

    new_callback = "http://%s:%d" % (ip, port)
    _common.log("Updating the callback to %s" % new_callback)
    _common.patch_regex(XSL_FILE, _common.CALLBACK_REGEX, new_callback)

    _common.execute([MS_XSL, XML_FILE, XSL_FILE])
    server.shutdown()


if __name__ == "__main__":
    exit(main())
