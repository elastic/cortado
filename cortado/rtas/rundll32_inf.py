# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import time

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="7d139669-2b4c-4fc3-9a7c-bd1b643696dc",
    platforms=["windows"],
    endpoint_rules=[
        RuleMetadata(id="93438ae3-becd-43fa-81de-645ce17afa8e", name="Scriptlet Execution via Rundll32"),
        RuleMetadata(id="f60455df-5054-49ff-9ff7-1dc4e37b6ea7", name="Binary Proxy Execution via Rundll32"),
    ],
    siem_rules=[],
    techniques=["T1218", "T1059"],
)

INF_FILE = _common.get_path("bin", "notepad_launch.inf")


@_common.requires_os(*metadata.platforms)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    _common.log("RunDLL32 with Script Object and Network Callback")
    server, ip, port = _common.serve_web()
    callback = "http://%s:%d" % (ip, port)
    _common.clear_web_cache()

    _common.patch_regex(INF_FILE, _common.CALLBACK_REGEX, callback)

    rundll32 = "rundll32.exe"
    _common.execute(
        [
            rundll32,
            "advpack.dll," + "LaunchINFSection",
            INF_FILE + ",DefaultInstall_SingleUser,1,",
        ],
        shell=False,
    )

    time.sleep(1)
    _common.log("Cleanup", log_type="-")
    _common.execute(["taskkill", "/f", "/im", "notepad.exe"])
    server.shutdown()


if __name__ == "__main__":
    exit(main())
