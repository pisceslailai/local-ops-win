#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows 受控进程锚点（总控台专用，仅 Windows 使用）。

由 server.py 的 _start_app_windows 拉起：argv[1] 是本次启动的随机标记
（console-run:<token>），argv[2] 是用户在启动台保存的命令字符串。

行为等价于 macOS 端的外层 bash 包装：
1. 把用户命令写入临时 .cmd 批处理文件，再以 ``cmd /d /c`` 执行
   （cmd 对含引号命令行的解析规则与 POSIX 完全不同，批处理文件是
   唯一能原样执行任意命令的稳妥通道）；文件以系统区域编码写入，
   与 cmd 的解析一致；
2. 直接子进程退出后继续等到整棵进程树清空再退出（对应 bash 的 ``wait``），
   因此“脚本把服务放后台后自己退出”的场景下锚点仍是受控身份锚；
3. 以直接子进程的退出码退出，供总控台记录任务成功/失败。

总控台自身重启不影响本锚点：锚点独立存活，受控身份由命令行标记 +
PPID 后代树识别（Windows 子进程在父进程退出后仍保留原 PPID）。
"""

import json
import locale
import os
import re
import subprocess
import sys
import tempfile
import time

CREATE_NO_WINDOW = 0x08000000
POLL_SEC = 2.0
TEMP_SUBDIR = "local-ops-console-anchor"
BATCH_MARKER = b"@rem local-ops-console-anchor:v1"
_BATCH_NAME_RE = re.compile(
    r"^anchor-(?P<pid>[1-9]\d*)-[a-z0-9_]+\.cmd$", re.IGNORECASE)

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    ERROR_NO_MORE_FILES = 18
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _KERNEL32.CreateToolhelp32Snapshot.argtypes = [
        wintypes.DWORD, wintypes.DWORD]
    _KERNEL32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _KERNEL32.Process32FirstW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _KERNEL32.Process32FirstW.restype = wintypes.BOOL
    _KERNEL32.Process32NextW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _KERNEL32.Process32NextW.restype = wintypes.BOOL
    _KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    _KERNEL32.CloseHandle.restype = wintypes.BOOL
else:  # pragma: no cover - 本脚本仅由 Windows 启动
    ctypes = None
    _KERNEL32 = None


def _anchor_temp_dir():
    """返回产品专属临时目录；拒绝符号链接或目录联接。"""
    directory = os.path.join(tempfile.gettempdir(), TEMP_SUBDIR)
    if os.path.lexists(directory):
        is_junction = getattr(os.path, "isjunction", lambda _path: False)
        if os.path.islink(directory) or is_junction(directory):
            raise OSError("anchor temp directory must not be a link")
        if not os.path.isdir(directory):
            raise OSError("anchor temp path is not a directory")
    else:
        os.makedirs(directory, mode=0o700)
    return directory


def _batch_file(command, directory=None):
    """写入带所有权标记的临时 .cmd，返回绝对路径。"""
    directory = directory or _anchor_temp_dir()
    encoding = locale.getpreferredencoding(False) or "utf-8"
    fd, path = tempfile.mkstemp(
        prefix="anchor-%d-" % os.getpid(), suffix=".cmd", dir=directory)
    with os.fdopen(fd, "w", encoding=encoding, errors="replace",
                   newline="\r\n") as f:
        f.write(BATCH_MARKER.decode("ascii") + "\r\n")
        f.write("@echo off\r\n")
        f.write(command + "\r\n")
        f.write("exit /b %errorlevel%\r\n")
    return path


def _cleanup_stale_batches(directory=None, active_pids=None):
    """删除死亡锚点遗留的本产品批处理；任何身份不确定都保留。"""
    directory = directory or _anchor_temp_dir()
    if active_pids is None:
        try:
            active_pids = set(_snapshot_ppids())
        except Exception:
            try:
                active_pids = set(_snapshot_ppids_powershell())
            except Exception:
                return 0
    else:
        active_pids = {int(pid) for pid in active_pids}
    removed = 0
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return 0
    for entry in entries:
        match = _BATCH_NAME_RE.fullmatch(entry.name)
        if not match or not entry.is_file(follow_symlinks=False):
            continue
        if int(match.group("pid")) in active_pids:
            continue
        try:
            with open(entry.path, "rb") as handle:
                if handle.read(len(BATCH_MARKER)) != BATCH_MARKER:
                    continue
            os.remove(entry.path)
            removed += 1
        except OSError:
            # 文件仍被 cmd 占用、权限不足或刚被其他锚点清理时均保守跳过。
            continue
    return removed


def _snapshot_ppids_powershell():
    """原生快照失败时的兼容回退；正常轮询路径不会启动 PowerShell。"""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-Command",
         "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
         "Get-CimInstance Win32_Process | "
         "Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress"],
        capture_output=True, timeout=10)
    if out.returncode != 0:
        raise OSError("PowerShell process snapshot failed")
    text = out.stdout.decode("utf-8", errors="replace") or ""
    try:
        items = json.loads(text)
    except ValueError as exc:
        raise OSError("invalid PowerShell process snapshot") from exc
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        raise OSError("invalid PowerShell process snapshot")
    parents = {}
    for item in items:
        try:
            pid = int(item.get("ProcessId") or 0)
            ppid = int(item.get("ParentProcessId") or 0)
        except (AttributeError, TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        parents[pid] = max(0, ppid)
    return parents


def _snapshot_ppids():
    """用 Toolhelp32 在进程内读取 ``pid -> ppid``，不创建辅助进程。"""
    if _KERNEL32 is None:  # pragma: no cover - 防止脚本被误用于非 Windows
        raise OSError("Toolhelp32 is only available on Windows")
    handle = _KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not handle or handle == INVALID_HANDLE_VALUE:
        raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
    parents = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not _KERNEL32.Process32FirstW(handle, ctypes.byref(entry)):
            error = ctypes.get_last_error()
            if error not in (0, ERROR_NO_MORE_FILES):
                raise OSError(error, "Process32FirstW failed")
            return parents
        while True:
            pid = int(entry.th32ProcessID)
            if pid > 0:
                parents[pid] = max(0, int(entry.th32ParentProcessID))
            entry.dwSize = ctypes.sizeof(entry)
            if not _KERNEL32.Process32NextW(handle, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error not in (0, ERROR_NO_MORE_FILES):
                    raise OSError(error, "Process32NextW failed")
                break
    finally:
        _KERNEL32.CloseHandle(handle)
    return parents


def _live_descendants(root_pid):
    """root 是否有存活后代（含隔代；父进程已退出的孤儿仍按 PPID 命中）。"""
    try:
        parents = _snapshot_ppids()
    except Exception:
        try:
            parents = _snapshot_ppids_powershell()
        except Exception:
            return True  # 两种查询均失败时保守认为仍在运行
    children = {}
    for pid, ppid in parents.items():
        if ppid > 0:
            children.setdefault(ppid, []).append(pid)
    stack = list(children.get(root_pid, []))
    seen = set()
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, []))
        return True
    return False


def main():
    if len(sys.argv) < 3:
        return 1
    _marker, command = sys.argv[1], sys.argv[2]
    try:
        temp_dir = _anchor_temp_dir()
        _cleanup_stale_batches(temp_dir)
        batch = _batch_file(command, directory=temp_dir)
    except OSError:
        return 1
    try:
        proc = subprocess.Popen(
            ["cmd", "/d", "/c", batch],
            creationflags=CREATE_NO_WINDOW)
    except OSError:
        try:
            os.remove(batch)
        except OSError:
            pass
        return 1
    try:
        code = proc.wait()
        try:
            while _live_descendants(proc.pid):
                time.sleep(POLL_SEC)
        except KeyboardInterrupt:
            pass
        return code if isinstance(code, int) else 1
    finally:
        try:
            os.remove(batch)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
