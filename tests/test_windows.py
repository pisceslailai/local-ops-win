# -*- coding: utf-8 -*-
"""Windows 适配层测试（macOS 上整体跳过）。

覆盖：netstat/CIM 解析、cmd 引号、PPID 树（含环）、PEB cwd、
PID 存活判定、Windows 命令生成、锚点进程的真实启停生命周期。
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import server


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipIf(not server.IS_WIN, "Windows 适配层专属测试")
class WindowsParsingTests(unittest.TestCase):
    def test_netstat_parse(self):
        text = (
            "\n"
            "Active Connections\n\n"
            "  Proto  Local Address          Foreign Address        State           PID\n"
            "  TCP    0.0.0.0:9600           0.0.0.0:0              LISTENING       1234\n"
            "  TCP    127.0.0.1:8899         0.0.0.0:0              LISTENING       5678\n"
            "  TCP    [::1]:8765             [::]:0                 LISTENING       9012\n"
            "  TCP    127.0.0.1:54321        127.0.0.1:0            ESTABLISHED     3456\n"
            "  TCP    0.0.0.0:9601           0.0.0.0:0              LISTENING       abc\n"
        )
        found = server._parse_netstat_output(text)
        self.assertEqual(found[(1234, 9600)], {"0.0.0.0"})
        self.assertEqual(found[(5678, 8899)], {"127.0.0.1"})
        self.assertEqual(found[(9012, 8765)], {"::1"})
        self.assertNotIn((3456, 54321), found)  # 非 LISTENING 跳过
        self.assertNotIn((None, 9601), found)   # 非数字 PID 跳过

    def test_cim_json_parse(self):
        text = json.dumps([
            {"ProcessId": 1, "ParentProcessId": 0, "Name": "System",
             "ExecutablePath": None, "CommandLine": None,
             "CreationDate": "20250401090000.000000+480", "WorkingSetSize": 0},
            {"ProcessId": 42, "ParentProcessId": 1, "Name": "python.exe",
             "ExecutablePath": "C:\\py\\python.exe", "CommandLine": "python -m http.server",
             "CreationDate": "2025-04-01T09:00:00Z", "WorkingSetSize": 1048576},
        ])
        table = server._parse_win_process_table_json(text)
        self.assertEqual(table[1]["ppid"], 0)
        self.assertEqual(table[42]["args"], "python -m http.server")
        self.assertEqual(table[42]["exe"], "C:\\py\\python.exe")
        self.assertEqual(server._parse_win_process_table_json(""), {})
        self.assertEqual(server._parse_win_process_table_json("not json"), {})

    def test_win_quote(self):
        self.assertEqual(server._win_quote("C:\\my dir\\job.py"),
                         '"C:\\my dir\\job.py"')
        self.assertEqual(server._win_quote('say "hi"'),
                         '"say ""hi"""')

    def test_win_parse_creation(self):
        dmtf = server._win_parse_creation("20250401090000.123456+480")
        self.assertIsNotNone(dmtf)
        iso = server._win_parse_creation("2025-04-01T09:00:00Z")
        self.assertIsNotNone(iso)
        ps51 = server._win_parse_creation("/Date(1743498000123+0800)/")
        self.assertAlmostEqual(ps51, 1743498000.123, places=3)
        self.assertIsNone(server._win_parse_creation(""))
        self.assertIsNone(server._win_parse_creation("garbage"))

    def test_win_tree_of_with_cycle(self):
        table = {
            1: {"ppid": 0}, 2: {"ppid": 1}, 3: {"ppid": 2},
            4: {"ppid": 3}, 5: {"ppid": 4},  # 5→4→3→2→1 正常链
            6: {"ppid": 7}, 7: {"ppid": 6},  # 环
        }
        tree = server._win_tree_of(1, table)
        self.assertEqual(tree[0], 1)
        self.assertEqual(set(tree), {1, 2, 3, 4, 5})
        cyclic = server._win_tree_of(6, table)
        self.assertEqual(set(cyclic), {6, 7})

    def test_netstat_fallback_does_not_depend_on_localized_state(self):
        text = (
            "TCP  0.0.0.0:9600  0.0.0.0:0  ABHÖREN  1234\n"
            "TCP  127.0.0.1:9601  0.0.0.0:0  EN ÉCOUTE  5678\n"
            "TCP  127.0.0.1:50000  127.0.0.1:443  ESTABLISHED  9999\n")
        found = server._parse_netstat_output(text)
        self.assertIn((1234, 9600), found)
        self.assertIn((5678, 9601), found)
        self.assertNotIn((9999, 50000), found)

    def test_win_command_for_script(self):
        cases = [
            ("C:\\path\\job.py", "py", 'py -3 -- "C:\\path\\job.py"'),
            ("C:\\path\\job.py", None, 'python -- "C:\\path\\job.py"'),
            ("C:\\path\\run.bat", None, '"C:\\path\\run.bat"'),
            ("C:\\path\\run.cmd", None, '"C:\\path\\run.cmd"'),
            ("C:\\path\\job.ps1", None,
             'powershell -NoProfile -ExecutionPolicy Bypass -File "C:\\path\\job.ps1"'),
            ("C:\\path\\job.sh", "bash", 'bash -- "C:\\path\\job.sh"'),
            ("C:\\path\\job.sh", None, '"C:\\path\\job.sh"'),
        ]
        for path, which_result, expected in cases:
            with self.subTest(path=path, which=which_result):
                def fake_which(name, which_result=which_result):
                    return which_result if which_result is not None else None
                with mock.patch.object(server.shutil, "which",
                                       side_effect=fake_which):
                    self.assertEqual(server.command_for_script(path), expected)


@unittest.skipIf(not server.IS_WIN, "Windows 适配层专属测试")
class WindowsProcessTests(unittest.TestCase):
    def test_pid_alive_detects_exit(self):
        proc = subprocess.Popen([sys.executable, "-c",
                                 "import time; time.sleep(30)"])
        try:
            self.assertTrue(server.pid_alive(proc.pid))
            proc.kill()
            proc.wait()
            deadline = time.time() + 3
            while time.time() < deadline and server.pid_alive(proc.pid):
                time.sleep(0.05)
            self.assertFalse(server.pid_alive(proc.pid))
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_instance_lock_exclusive(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "lock")
            first = server.acquire_instance_lock(path)
            second = server.acquire_instance_lock(path)
            self.assertIsNotNone(first)
            self.assertIsNone(second)
            server.release_instance_lock(first)
            third = server.acquire_instance_lock(path)
            self.assertIsNotNone(third)
            server.release_instance_lock(third)

    def test_win_cwd_reads_own_directory(self):
        cwd = server._win_cwd(server.SELF_PID)
        self.assertIsNotNone(cwd)
        self.assertEqual(os.path.realpath(cwd), os.path.realpath(os.getcwd()))

    def test_process_owner_matches_current_sid(self):
        self.assertEqual(server.process_uid(server.SELF_PID), server.SELF_UID)

    def _config_with_app(self, directory, app):
        path = os.path.join(directory, "config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**server.Config.DEFAULT, "apps": [app]}, f)
        return server.Config(path)

    def test_task_exit_code_survives_cmd_wrapper(self):
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(server, "LOGS_DIR", td):
            app = {**server.Config.APP_DEFAULT, "id": "win000001",
                   "kind": "task", "cwd": td,
                   "command": "python -c \"import sys; sys.exit(130)\""}
            ok, error, proc, _, _ = server.start_app(app)
            self.assertTrue(ok, error)
            try:
                self.assertEqual(proc.wait(timeout=20), 130)
            finally:
                if server.pid_alive(proc.pid):
                    server.stop_pid_tree(proc.pid)

    def test_service_lifecycle_managed_stop(self):
        port = _free_port()
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(server, "LOGS_DIR", td):
            base = {**server.Config.APP_DEFAULT, "id": "win000002",
                    "name": "Service", "cwd": td,
                    "command": "python -m http.server %d" % port}
            cfg = self._config_with_app(td, base)
            ok, error, proc, pgid, token = server.start_app(base)
            self.assertTrue(ok, error)
            server.persist_started_app(cfg, base["id"], proc, pgid, token)
            tracked = server.find_app(cfg.snapshot(), base["id"])
            try:
                deadline = time.time() + 10
                managed = []
                while time.time() < deadline and not managed:
                    time.sleep(0.3)
                    managed = server.managed_pids(tracked)
                self.assertTrue(managed, "受管进程未被识别")
                # token 校验：锚点命令行应带本次启动的随机标记
                snap = server.ps_snapshot({proc.pid})
                self.assertIn("console-run:" + token,
                              snap.get(proc.pid, {}).get("args", ""))
                self.assertIn(port, {p for _, p in server.scan_listeners()})
                stopped, error = server.stop_app_and_clear(
                    cfg, tracked, timeout=10)
                self.assertTrue(stopped, error)
                self.assertFalse(server.pid_alive(proc.pid))
                self.assertNotIn(port, {p for _, p in server.scan_listeners()})
            finally:
                if server.pid_alive(proc.pid):
                    server.stop_pid_tree(proc.pid)

    def test_win_launch_env_keeps_path_and_token(self):
        env = server.build_launch_env("win-secret", {"PATH": "C:\\bin"})
        self.assertEqual(env["PATH"], "C:\\bin")
        self.assertEqual(env[server.RUN_TOKEN_ENV], "win-secret")


if __name__ == "__main__":
    unittest.main()
