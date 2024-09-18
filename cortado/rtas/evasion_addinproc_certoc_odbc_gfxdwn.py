# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

import logging

from . import OSType, RuleMetadata, _common, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="6e84852e-b8a2-4158-971e-c5148d969d2a",
    name="evasion_addinproc_certoc_odbc_gfxdwn",
    platforms=[OSType.WINDOWS],
    siem_rules=[],
    endpoint_rules=[
        RuleMetadata(id="5bc7a8f8-4de8-4af4-bea4-cba538e54a5c", name="Suspicious Execution via DotNet Remoting"),
        RuleMetadata(id="6fcbf73f-4413-4689-be33-61b0d6bd0ffc", name="Suspicious ImageLoad via Windows CertOC"),
        RuleMetadata(
            id="1faebe83-38d7-4390-b6bd-9c6b851e47c4", name="Suspicious ImageLoad via ODBC Driver Configuration Program"
        ),
        RuleMetadata(id="aafe3c78-15d9-4853-a602-663b8fada5b5", name="Potential Evasion via Intel GfxDownloadWrapper"),
    ],
    techniques=["T1218", "T1218.008", "T1105"],
)
def main():
    EXE_FILE = _common.get_resource_path("bin/renamed_posh.exe")

    addinproc = "C:\\Users\\Public\\AddInProcess.exe"
    certoc = "C:\\Users\\Public\\CertOc.exe"
    odbc = "C:\\Users\\Public\\odbcconf.exe"
    gfxdwn = "C:\\Users\\Public\\GfxDownloadWrapper.exe"

    _common.copy_file(EXE_FILE, addinproc)
    _common.copy_file(EXE_FILE, certoc)
    _common.copy_file(EXE_FILE, odbc)
    _common.copy_file(EXE_FILE, gfxdwn)

    # Execute command
    _ = _common.execute_command([addinproc, "/guid:32a91b0f-30cd-4c75-be79-ccbd6345de99", "/pid:123"], timeout_secs=10)
    _ = _common.execute_command([certoc, "-LoadDLL"], timeout_secs=10)
    _ = _common.execute_command([odbc, "-a", "-f"], timeout_secs=10)
    _ = _common.execute_command([gfxdwn, "run", "2", "0"], timeout_secs=10)

    # Cleanup
    _common.remove_file(addinproc)
    _common.remove_file(certoc)
    _common.remove_file(odbc)
    _common.remove_file(gfxdwn)
