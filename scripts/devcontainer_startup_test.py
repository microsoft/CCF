#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import contextlib
import json
import os
from pathlib import Path
import pty
import signal
import stat
import subprocess
import tempfile
import time
import unittest


class DevcontainerStartupTest(unittest.TestCase):
    def setUp(self):
        repo = Path(__file__).resolve().parents[1]
        config = json.loads(
            (repo / ".devcontainer/azurelinux4-copilotd/devcontainer.json").read_text()
        )
        self.command = config["postStartCommand"]

    def test_relay_survives_pty_hook_exit(self):
        """Run the real hook with test-only startup scripts, without credentials."""

        for attempt in range(10):
            with self.subTest(attempt=attempt), tempfile.TemporaryDirectory() as temp:
                workspace = Path(temp)
                home = workspace / "home"
                ssh_startup = workspace / ".devcontainer/sshd/start_sshd.sh"
                ssh_startup.parent.mkdir(parents=True)
                ssh_startup.write_text("printf 'started\\n' > \"$HOME/sshd-started\"\n")
                startup = (
                    workspace / ".devcontainer/azurelinux4-copilotd/start_copilotd.sh"
                )
                startup.parent.mkdir(parents=True)
                startup.write_text(
                    "#!/bin/bash\n"
                    "set -eu\n"
                    'test -f "$HOME/sshd-started"\n'
                    "printf 'startup ready\\n'\n"
                    'printf \'%s\\n\' "$$" > "$HOME/startup.pid.tmp"\n'
                    'mv "$HOME/startup.pid.tmp" "$HOME/startup.pid"\n'
                    "exec sleep 60\n"
                )
                pid_file = home / "startup.pid"
                log = home / ".local/state/ccf-copilotd/copilotd.log"
                hook_exited = False
                hook_pid, terminal = pty.fork()
                if hook_pid == 0:
                    os.chdir(workspace)
                    os.execvpe(
                        self.command[0],
                        self.command,
                        {"HOME": str(home), "PATH": os.environ["PATH"]},
                    )

                try:
                    deadline = time.monotonic() + 5
                    waited_pid = 0
                    while time.monotonic() < deadline:
                        waited_pid, status = os.waitpid(hook_pid, os.WNOHANG)
                        if waited_pid:
                            hook_exited = True
                            break
                        time.sleep(0.01)
                    self.assertEqual(
                        waited_pid, hook_pid, "The hook must not block startup"
                    )
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0)

                    deadline = time.monotonic() + 5
                    while not pid_file.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(
                        pid_file.exists(), "The background startup did not survive"
                    )
                    startup_pid = int(pid_file.read_text())
                    os.kill(startup_pid, 0)
                    self.assertEqual(os.getsid(startup_pid), startup_pid)
                    self.assertNotEqual(startup_pid, hook_pid)
                    self.assertEqual(log.read_text(), "startup ready\n")
                    self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
                finally:
                    if pid_file.exists():
                        with contextlib.suppress(ProcessLookupError):
                            os.kill(int(pid_file.read_text()), signal.SIGTERM)
                    if not hook_exited:
                        with contextlib.suppress(ProcessLookupError):
                            os.kill(hook_pid, signal.SIGKILL)
                        os.waitpid(hook_pid, 0)
                    os.close(terminal)

    def test_ssh_failure_is_reported_by_hook(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            home = workspace / "home"
            ssh_startup = workspace / ".devcontainer/sshd/start_sshd.sh"
            ssh_startup.parent.mkdir(parents=True)
            ssh_startup.write_text("printf 'test SSH startup failed\\n' >&2\nexit 42\n")
            result = subprocess.run(
                self.command,
                cwd=workspace,
                env={"HOME": str(home), "PATH": os.environ["PATH"]},
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 42)
            self.assertIn("test SSH startup failed", result.stderr)
            self.assertFalse((home / ".local/state/ccf-copilotd/copilotd.log").exists())


if __name__ == "__main__":
    unittest.main()
