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
import subprocess
import sys
import tempfile
import time

CREATE_NO_WINDOW = 0x08000000
POLL_SEC = 2.0


def _batch_file(command):
    """写入临时 .cmd 文件，返回其路径。调用方负责删除。"""
    encoding = locale.getpreferredencoding(False) or "utf-8"
    fd, path = tempfile.mkstemp(prefix="console-", suffix=".cmd")
    with os.fdopen(fd, "w", encoding=encoding, errors="replace",
                   newline="\r\n") as f:
        f.write("@echo off\r\n")
        f.write(command + "\r\n")
        f.write("exit /b %errorlevel%\r\n")
    return path


def _live_descendants(root_pid):
    """root 是否有存活后代（含隔代；父进程已退出的孤儿仍按 PPID 命中）。"""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
             "Get-CimInstance Win32_Process | "
             "Select-Object ProcessId,ParentProcessId | ConvertTo-Json -Compress"],
            capture_output=True, timeout=10)
        text = out.stdout.decode("utf-8", errors="replace") or ""
    except Exception:
        return True  # 查询失败时保守认为仍在运行
    try:
        items = json.loads(text)
    except ValueError:
        return True
    if isinstance(items, dict):
        items = [items]
    children = {}
    for item in items:
        try:
            pid = int(item.get("ProcessId") or 0)
            ppid = int(item.get("ParentProcessId") or 0)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
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
    batch = _batch_file(command)
    try:
        proc = subprocess.Popen(
            ["cmd", "/d", "/c", batch],
            creationflags=CREATE_NO_WINDOW)
    except OSError:
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
