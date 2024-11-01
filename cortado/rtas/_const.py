# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

DEFAULT_POWERSHELL_PATH = "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

CATCH_ALL_IP = "0.0.0.0"

IP_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
CALLBACK_REGEX = r"https?://" + IP_REGEX + r":\d+"

REG_HKLM = "hklm"
REG_HKCU = "hkcu"
REG_HKU = "hku"
REG_HKCR = "hkcr"

SZ = "sz"
EXPAND_SZ = "expand_sz"
MULTI_SZ = "multi_sz"
DWORD = "dword"

PS_EXEC_EXE = "bin\\PsExec.exe"

# Return codes

## Custom code for Cortado code
RTA_SUBPROCESS_TIMEOUT_RETURNCODE = 124

ACCESS_DENIED_RETURNCODE = 5
