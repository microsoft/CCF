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
import tempfile
import time
import unittest


class DevcontainerStartupTest(unittest.TestCase):
    def test_relay_survives_pty_hook_exit(self):
        """Run the real hook with a test-only startup script, without credentials."""
        repo = Path(__file__).resolve().parents[1]
        config = json.loads(
            (repo / ".devcontainer/azurelinux4-copilotd/devcontainer.json").read_text()
        )
        command = config["postStartCommand"]

        for attempt in range(10):
            with self.subTest(attempt=attempt), tempfile.TemporaryDirectory() as temp:
                workspace = Path(temp)
                home = workspace / "home"
                startup = (
                    workspace / ".devcontainer/azurelinux4-copilotd/start_copilotd.sh"
                )
                startup.parent.mkdir(parents=True)
                startup.write_text(
                    "#!/bin/bash\n"
                    "set -eu\n"
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
                        command[0],
                        command,
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


if __name__ == "__main__":
    unittest.main()
