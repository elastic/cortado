# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.
# Adjusted version of https://github.com/XRoemer/Organon/blob/master/source/py/rawinputdata.py

import logging
import time

from . import OSType, RuleMetadata, register_code_rta

log = logging.getLogger(__name__)


@register_code_rta(
    id="89f2b412-bbc7-4298-8768-2f3d3b43c93b",
    name="collection_keylog_rawinputdevice",
    platforms=[OSType.WINDOWS],
    endpoint_rules=[
        RuleMetadata(id="102b5c1a-7f2a-4254-8b26-6b299705fce7", name="Keystroke Input Capture via DirectInput"),
        RuleMetadata(
            id="4dbb9dfb-b3e2-49d7-8919-d6f221526df4", name="Keystroke Input Capture via RegisterRawInputDevices"
        ),
    ],
    techniques=["T1056", "T1056.001"],
)
def main():
    from ctypes import WINFUNCTYPE  # type: ignore
    from ctypes import Union  # type: ignore
    from ctypes import WinError  # type: ignore
    from ctypes import sizeof  # type: ignore
    from ctypes import windll  # type: ignore
    from ctypes import Structure, byref, c_int, c_long, c_uint, c_ushort, pointer
    from ctypes.wintypes import BYTE, DWORD, HANDLE, HINSTANCE, HWND, LONG, LPCSTR, LPVOID, UINT, ULONG, WPARAM

    wndproc = WINFUNCTYPE(c_long, c_int, c_uint, c_int, c_int)  # type: ignore

    class WNDCLASS(Structure):
        _fields_ = [  #  type: ignore
            ("style", c_uint),
            ("lpfnWndProc", wndproc),
            ("cbClsExtra", c_int),
            ("cbWndExtra", c_int),
            ("hInstance", HINSTANCE),
            ("hIcon", HANDLE),
            ("hCursor", HANDLE),
            ("hbrBackground", HANDLE),
            ("lpszMenuName", LPCSTR),
            ("lpszClassName", LPCSTR),
        ]

    class POINT(Structure):
        _fields_ = [("x", c_long), ("y", c_long)]

    class MSG(Structure):
        _fields_ = [
            ("hwnd", c_int),
            ("message", c_uint),
            ("wparam", c_int),
            ("lparam", c_int),
            ("time", c_int),
            ("pt", POINT),
        ]

    class RAWINPUTDEVICE(Structure):
        _fields_ = [
            ("usUsagePage", c_ushort),
            ("usUsage", c_ushort),
            ("dwFlags", DWORD),
            ("hwndTarget", HWND),
        ]

    class RAWINPUTHEADER(Structure):
        _fields_ = [
            ("dwType", DWORD),
            ("dw_size", DWORD),
            ("hDevice", HANDLE),
            ("wparam", WPARAM),
        ]

    class RAWMOUSE(Structure):
        class _U1(Union):
            class _S2(Structure):
                _fields_ = [
                    ("usButtonFlags", c_ushort),
                    ("usButtonData", c_ushort),
                ]

            _fields_ = [
                ("ulButtons", ULONG),
                ("_s2", _S2),
            ]

        _fields_ = [
            ("usFlags", c_ushort),
            ("_u1", _U1),
            ("ulRawButtons", ULONG),
            ("lLastX", LONG),
            ("lLastY", LONG),
            ("ulExtraInformation", ULONG),
        ]
        _anonymous_ = ("_u1",)

    class RAWKEYBOARD(Structure):
        _fields_ = [
            ("MakeCode", c_ushort),
            ("Flags", c_ushort),
            ("Reserved", c_ushort),
            ("VKey", c_ushort),
            ("Message", UINT),
            ("ExtraInformation", ULONG),
        ]

    class RAWHID(Structure):
        _fields_ = [
            ("dw_sizeHid", DWORD),
            ("dwCount", DWORD),
            ("bRawData", BYTE),
        ]

    class RAWINPUT(Structure):
        class _U1(Union):
            _fields_ = [
                ("mouse", RAWMOUSE),
                ("keyboard", RAWKEYBOARD),
                ("hid", RAWHID),
            ]

        _fields_ = [
            ("header", RAWINPUTHEADER),
            ("_u1", _U1),
            ("hDevice", HANDLE),
            ("wparam", WPARAM),
        ]
        _anonymous_ = ("_u1",)

    class RawInputReader:
        def __init__(self):
            pass

        def start(self):
            ws_overlapped_window = 0 | 12582912 | 524288 | 262144 | 131072 | 65536
            cw_use_default = -2147483648

            try:
                createwindowex = windll.user32.CreateWindowExA  # type: ignore
                createwindowex.argtypes = [
                    DWORD,
                    LPCSTR,
                    LPCSTR,
                    DWORD,
                    c_int,
                    c_int,
                    c_int,
                    c_int,
                    HANDLE,
                    HANDLE,
                    HANDLE,
                    LPVOID,
                ]
                createwindowex.restype = HANDLE
                wndclass = self.get_window()
                # Create Window
                hwnd = createwindowex(  # type: ignore
                    0,
                    wndclass.lpszClassName,
                    b"Python Window",
                    ws_overlapped_window,
                    cw_use_default,
                    cw_use_default,
                    cw_use_default,
                    cw_use_default,
                    0,
                    0,
                    wndclass.hInstance,
                    0,
                )

                if hwnd == 0:
                    print(WinError())  # type: ignore
                # Register for raw input
                raw_input_device = (2 * RAWINPUTDEVICE)()
                self.Rid = raw_input_device
                raw_input_device[0].usUsagePage = 0x01
                raw_input_device[0].usUsage = 0x06
                ridev_input_sink = 0x00000100  # Get events even when not focused
                raw_input_device[0].dwFlags = ridev_input_sink
                raw_input_device[0].hwndTarget = hwnd
                raw_input_device[1].usUsagePage = 0x01
                raw_input_device[1].usUsage = 0x02
                raw_input_device[1].dwFlags = ridev_input_sink
                raw_input_device[1].hwnTarget = hwnd

                registerrawinputdevices = windll.user32.RegisterRawInputDevices  # type: ignore
                registerrawinputdevices(raw_input_device, 2, sizeof(RAWINPUTDEVICE))
                self.hwnd = hwnd  # type: ignore

            except Exception as e:
                print("error starting")
                print(e)

        def get_window(self):
            cs_vredraw = 1
            cs_hredraw = 2
            idi_application = 32512
            idc_arrow = 32512
            white_brush = 0

            # Define Window Class
            wndclass = WNDCLASS()
            self.wndclass = wndclass
            wndclass.style = cs_hredraw | cs_vredraw
            wndclass.lpfnWndProc = wndproc(lambda h, m, w, x: self.wndproc(h, m, w, x))  #  type: ignore
            wndclass.cbClsExtra = wndclass.cbWndExtra = 0
            wndclass.hInstance = windll.kernel32.GetModuleHandleA(c_int(0))  # type: ignore
            wndclass.hIcon = windll.user32.LoadIconA(c_int(0), c_int(idi_application))  # type: ignore
            wndclass.hCursor = windll.user32.LoadCursorA(c_int(0), c_int(idc_arrow))  # type: ignore
            wndclass.hbrBackground = windll.gdi32.GetStockObject(c_int(white_brush))  # type: ignore
            wndclass.lpszMenuName = None
            wndclass.lpszClassName = b"MainWin"

            if not windll.user32.RegisterClassA(byref(wndclass)):  # type: ignore
                print("error in RegisterClassA")
                raise WinError()

            return wndclass

        def poll_events(self):
            # Pump Messages
            msg = MSG()
            pmsg = pointer(msg)

            pm_remove = 1

            while windll.user32.PeekMessageA(pmsg, self.hwnd, 0, 0, pm_remove) != 0:  # type: ignore
                windll.user32.DispatchMessageA(pmsg)  # type: ignore

        def __del__(self):
            pass

        def stop(self):
            self.Rid[0].dwFlags = 0x00000001
            windll.user32.DestroyWindow(self.hwnd)  # type: ignore

        def wndproc(self, hwnd, message, wparam, lparam):  # type: ignore
            try:
                wm_input = 255
                ri_mouse_wheel = 0x0400
                wm_destroy = 2

                if message == wm_destroy:
                    windll.user32.PostQuitMessage(0)  # type: ignore
                    return 0

                elif message == wm_input:
                    get_raw_input_data = windll.user32.get_raw_input_data  # type: ignore
                    null = c_int(0)
                    dw_size = c_uint()
                    rid_input = 0x10000003
                    get_raw_input_data(lparam, rid_input, null, byref(dw_size), sizeof(RAWINPUTHEADER))

                    if dw_size.value == 40:
                        # Mouse
                        raw = RAWINPUT()

                        if (
                            get_raw_input_data(lparam, rid_input, byref(raw), byref(dw_size), sizeof(RAWINPUTHEADER))
                            == dw_size.value
                        ):
                            rim_typemouse = 0x00000000

                            if raw.header.dwType == rim_typemouse:
                                if raw.mouse._u1._s2.usButtonFlags != ri_mouse_wheel:
                                    return 0

                return windll.user32.DefWindowProcA(c_int(hwnd), c_int(message), c_int(wparam), c_int(lparam))  # type: ignore

            except Exception as e:
                print("general exception in wndproc")
                print(e)

    rir = RawInputReader()
    rir.start()
    time.sleep(5)
    rir.stop()
