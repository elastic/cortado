# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="1796555f-921a-459f-9661-0d94cf90fe81",
    platforms=[OSType.MACOS],
    endpoint_rules=[
        RuleMetadata(id="7dea8cfc-92db-4081-9a5d-85ead8cedd5f", name="Potential SIP Bypass via the ShoveService")
    ],
    siem_rules=[],
    techniques=["T1068"],
)
def main():
    masquerade = "/tmp/sh"
    _common.create_macos_masquerade(masquerade)

    _common.log("Executing shove processes to mimic sip bypass.")
    command = "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/shove -x"
    _common.execute([masquerade, "childprocess", command], shell=True, timeout=5, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
