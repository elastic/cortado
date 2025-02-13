# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="d6c94638-5c8a-40e9-9ad8-86a8f97cc043",
    name="network_connection_nslookup",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[],
    siem_rules=[RuleMetadata(id="3a59fc81-99d3-47ea-8cd6-d48d561fca20", name="Potential DNS Tunneling via NsLookup")],
    techniques=["T1071", "T1071.004"],
)
def main():
    nslookup = "C:\\Windows\\System32\\nslookup.exe"

    # Execute command 15 times
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
    _ = _common.execute_command([nslookup, "-q=aaaa", "google.com"], timeout_secs=10)
