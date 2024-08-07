# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: RunDll32 with .inf Callback
# RTA: rundll32_inf_callback.py
# signal.rule.name: Local Service Commands
# signal.rule.name: Potential Modification of Accessibility Binaries
# ATT&CK: T1105
# Description: Loads RunDll32 with a suspicious .inf file that makes a local http GET

import time

from . import _common


INF_FILE = "bin/script_launch.inf"


@register_code_rta(
    id="a2edc784-e969-45f4-b8d2-fe4556b42cd6",
    platforms=[OSType.WINDOWS],
    ancillary_files=[INF_FILE],
)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    _common.log("RunDLL32 with Script Object and Network Callback")
    server, ip, port = _common.serve_web()
    callback = "http://%s:%d" % (ip, port)
    _common.clear_web_cache()

    _common.patch_regex(INF_FILE, _common.CALLBACK_REGEX, callback)

    rundll32 = "rundll32.exe"
    dll_entrypoint = "setupapi.dll,InstallHinfSection"
    _common.execute([rundll32, dll_entrypoint, "DefaultInstall", "128", INF_FILE], shell=False)

    time.sleep(1)
    _common.log("Cleanup", log_type="-")
    _common.execute(["taskkill", "/f", "/im", "notepad.exe"])
    server.shutdown()
