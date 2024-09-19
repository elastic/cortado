# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging
import time

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="7d139669-2b4c-4fc3-9a7c-bd1b643696dc",
    name="rundll32_inf",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="93438ae3-becd-43fa-81de-645ce17afa8e", name="Scriptlet Execution via Rundll32"),
        RuleMetadata(id="f60455df-5054-49ff-9ff7-1dc4e37b6ea7", name="Binary Proxy Execution via Rundll32"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1059"],
)
def main():
    INF_FILE = _common.get_resource_path("bin/notepad_launch.inf")

    # http server will terminate on main thread exit
    # if daemon is True
    log.info("RunDLL32 with Script Object and Network Callback")
    server, ip, port = _common.serve_dir_over_http()
    callback = "http://%s:%d" % (ip, port)
    _common.clear_web_cache()

    _common.patch_regex(INF_FILE, _common.CALLBACK_REGEX, callback)

    rundll32 = "rundll32.exe"
    _ = _common.execute_command(
        [
            rundll32,
            "advpack.dll," + "LaunchINFSection",
            INF_FILE + ",DefaultInstall_SingleUser,1,",
        ],
        shell=False,
    )

    time.sleep(1)
    log.info("Cleanup")
    _ = _common.execute_command(["taskkill", "/f", "/im", "notepad.exe"])
    server.shutdown()
