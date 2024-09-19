# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Outbound SMB from a User Process
# RTA: smb_connection.py
# ATT&CK: T1105
# Description: Initiates an SMB connection to a target machine, without going through the normal Windows APIs.

import logging
import socket

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)

SMB_PORT = 445


@register_code_rta(
    id="b0e3e1bb-dfa5-473a-8862-b2d1d42819ce",
    name="smb_connection",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="c82c7d8f-fb9e-4874-a4bd-fd9e3f9becf1", name="Direct Outbound SMB Connection")],
    techniques=["T1021"],
)
def main():
    ip = _common.get_host_ip()

    # connect to rpc
    log.info("Connecting to {}:{}".format(ip, SMB_PORT))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, 445))
    log.info("Sending HELLO")
    _ = s.send(b"HELLO!")
    log.info("Shutting down the connection...")
    s.close()
    log.info("Closed connection to {}:{}".format(ip, SMB_PORT))
