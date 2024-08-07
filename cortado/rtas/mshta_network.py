# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Microsoft HTA tool (mshta.exe) with Network Callback
# RTA: mshta_network.py
# ATT&CK: T1170
# Description: Generates network traffic from mshta.exe

from . import _common


HTA_FILE = _common.get_path("bin", "beacon.hta")


@register_code_rta(
    id="83465fca-25ae-4d6d-b747-c82cda75b0ae",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(
            id="1fe3b299-fbb5-4657-a937-1d746f2c711a", name="Unusual Network Activity from a Windows System Binary"
        ),
        RuleMetadata(id="c2d90150-0133-451c-a783-533e736c12d7", name="Mshta Making Network Connections"),
        RuleMetadata(id="a4ec1382-4557-452b-89ba-e413b22ed4b8", name="Network Connection via Mshta"),
    ],
    techniques=["T1127", "T1218"],
)
@_common.dependencies(HTA_FILE)
def main():
    # http server will terminate on main thread exit
    # if daemon is True
    _common.log("MsHta Beacon")
    server, ip, port = _common.serve_web()
    _common.clear_web_cache()

    new_callback = "http://%s:%d" % (ip, port)
    _common.log("Updating the callback to %s" % new_callback)
    _common.patch_regex(HTA_FILE, _common.CALLBACK_REGEX, new_callback)

    mshta = "mshta.exe"
    _common.execute([mshta, HTA_FILE], timeout=3, kill=True)
    server.shutdown()
