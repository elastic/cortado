# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import _common, RuleMetadata, register_code_rta, OSType

import time, sys

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
HC_ACTION = 0
hHook = None


@register_code_rta(
    id="19b7c8db-0279-41fe-b07d-481818185a10",
    name="collection_keylog_hook_keystate",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(
            id="2ed0570d-3fa4-45b1-b4f2-d7fcc827daf1", name="Suspicious Input Capture via GetAsyncKeyState API"
        ),
        RuleMetadata(
            id="be7140ba-4633-46a7-ac59-91cc85e5e252", name="GetAsyncKeyState API Call from Suspicious Process"
        ),
        RuleMetadata(id="7ae180e1-e08f-40c2-82db-f274f688eea2", name="keystroke Messages Hooking via SetWindowsHookEx"),
        RuleMetadata(
            id="6ef43c9a-25af-449c-8416-20349780a146", name="Keystrokes Input Capture from Suspicious CallStack"
        ),
    ],
    siem_rules=[],
    techniques=["T1056", "T1056.001"],
)
def GetAsyncKeyState():
    from ctypes import windll

    user32 = windll.user32

    special_keys = {
        0x08: "BS",
        0x09: "Tab",
        0x0D: "Enter",
        0x10: "Shift",
        0x11: "Ctrl",
        0x12: "Alt",
        0x14: "CapsLock",
        0x1B: "Esc",
        0x20: "Space",
        0x2E: "Del",
    }

    # reset key states
    for i in range(256):
        user32.GetAsyncKeyState(i)

    start = time.time()
    while time.time() - start < 5:
        for i in range(256):
            if user32.GetAsyncKeyState(i) & 1:
                if i in special_keys:
                    print("<{}>".format(special_keys[i]))
                elif 0x30 <= i <= 0x5A:
                    print("{:c}".format(i))
                else:
                    print("{:02x}".format(i))
        time.sleep(0.01)
        sys.stdout.flush()


def hook_procedure(code, w_param, l_paraml):
    import ctypes

    global hHook
    user32 = ctypes.windll.user32

    if code == HC_ACTION and w_param == WM_KEYDOWN:
        print("Key down")

    return user32.CallNextHookEx(hHook, code, w_param, l_paraml)


def SetWindowsHookEx():
    import ctypes
    from ctypes.wintypes import LPARAM, WPARAM

    global hHook
    user32 = ctypes.windll.user32
    hookproc = ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_int, WPARAM, LPARAM)
    proc = hookproc(hook_procedure)
    hHook = user32.SetWindowsHookExA(WH_KEYBOARD_LL, proc, 0, 0)

    start = time.time()
    while True:
        user32.PeekMessageA(0, 0, 0, 0, 0)
        time.sleep(0.01)
        if time.time() >= (start + 5):
            print("Finished")
            break


def main():
    SetWindowsHookEx()
    GetAsyncKeyState()
