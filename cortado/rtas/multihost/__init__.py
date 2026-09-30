# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Multi-host RTAs: scenarios whose roles run on separate hosts (e.g. a protocol server and client).
#
# Each module registers one RTA with `register_multihost_rta` (module name == RTA name) and its roles with
# `@rta.role(...)`. Reusable protocol code belongs in `cortado.rtas._protocols`, the runtime in
# `cortado.rtas._multihost`. Run with `cortado-run-multihost-rta`.
