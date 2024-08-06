# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

# Name: Certutil Encode / Decode
# RTA: certutil_file_obfuscation.py
# ATT&CK: T1140
# signal.rule.name: Encoding or Decoding Files via CertUtil
# Description: Uses certutil to create an encoded copy of cmd.exe. Then uses certutil to decode that copy.

from pathlib import Path

from . import RtaMetadata, _common

metadata = RtaMetadata(
    id="7b2c1b3e-2097-4e2f-bf5c-e157a91b8001",
    platforms=["windows"],
    endpoint_rules=[],
    siem_rules=[{"rule_id": "fd70c98a-c410-42dc-a2e3-761c71848acf", "rule_name": "Suspicious CertUtil Commands"}],
    techniques=["T1140"],
)


@_common.requires_os(*metadata.platforms)
def main():
    _common.log("Encoding target")
    encoded_file = Path("encoded.txt").resolve()
    decoded_file = Path("decoded.exe").resolve()
    _common.execute(
        [
            "c:\\Windows\\System32\\certutil.exe",
            "-encode",
            "c:\\windows\\system32\\cmd.exe",
            encoded_file,
        ]
    )

    _common.log("Decoding target")
    _common.execute(["c:\\Windows\\System32\\certutil.exe", "-decode", encoded_file, decoded_file])

    _common.log("Cleaning up")
    _common.remove_file(encoded_file)
    _common.remove_file(decoded_file)


if __name__ == "__main__":
    exit(main())
