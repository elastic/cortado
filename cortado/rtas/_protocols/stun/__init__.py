# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Constrained STUN/TURN-like task channel for detection research.
#
# - `codec`: strict STUN framing, TURN-like Data Indications, and HMAC-signed JSON payloads
# - `transports`: cleartext UDP transport and message framing (stdlib only)
# - `tls_stdlib`: TLS-PSK over TCP with the standard library (Python 3.13+)
# - `mbedtls_transport`: DTLS-PSK over UDP, and TLS on Python 3.12 (requires the optional `python-mbedtls` package)
# - `harness`: server/client sessions with a fixed, in-memory action allowlist
#
# This is not a TURN implementation: there are no allocations, permissions, channels, or peer relays.
# Data Indications omit `XOR-PEER-ADDRESS` and are useful as framing samples only.
