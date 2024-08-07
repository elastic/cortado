# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="214db941-51ba-4867-b9bf-9b22ff07eea8",
    platforms=[OSType.MACOS],
    endpoint_rules=[],
    siem_rules=[
        RuleMetadata(id="37f638ea-909d-4f94-9248-edd21e4a9906", name="Finder Sync Plugin Registered and Enabled")
    ],
    techniques=["T1543"],
)
def main():
    masquerade = "/tmp/pluginkit"
    _common.create_macos_masquerade(masquerade)

    # Execute command
    _common.log("Launching fake commands to miic finder sync plugins.")
    _common.execute([masquerade, "-a"], timeout=1, kill=True)
    _common.execute([masquerade, "-e", "use", "-i"], timeout=1, kill=True)

    # cleanup
    _common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
