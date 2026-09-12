# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import signal
import subprocess
from pathlib import Path
from unittest import mock

import infra.remote


def make_remote(tmp_path, node_container_image=None):
    remote = infra.remote.LocalRemote(
        "node_0",
        "localhost",
        [],
        [],
        ["./js_generic", "--config", "0.config.json"],
        str(tmp_path),
        str(tmp_path / "common"),
        env={"UBSAN_OPTIONS": "print_stacktrace=1"},
        node_container_image=node_container_image,
    )
    Path(remote.root).mkdir()
    return remote


def test_container_setup_copies_executables(tmp_path):
    remote = make_remote(tmp_path, "ccf:test")

    with mock.patch.object(remote, "_setup_files") as setup_files:
        remote.setup()

    setup_files.assert_called_once_with(False)


def test_container_start_uses_host_network_and_workspace(tmp_path):
    remote = make_remote(tmp_path, "ccf:test")
    process = mock.Mock()

    with (
        mock.patch("infra.remote.shutil.which", return_value="/usr/bin/docker"),
        mock.patch("infra.remote.subprocess.Popen", return_value=process) as popen,
    ):
        remote.start()

    root = os.path.abspath(remote.root)
    launch_cmd = popen.call_args.args[0]
    assert launch_cmd[:4] == [
        "/usr/bin/docker",
        "run",
        "--rm",
        "--name",
    ]
    assert ["--network", "host"] == launch_cmd[
        launch_cmd.index("--network") : launch_cmd.index("--network") + 2
    ]
    assert ["--volume", f"{root}:{root}"] == launch_cmd[
        launch_cmd.index("--volume") : launch_cmd.index("--volume") + 2
    ]
    assert launch_cmd[-4:] == [
        "ccf:test",
        "./js_generic",
        "--config",
        "0.config.json",
    ]
    assert popen.call_args.kwargs["env"] == os.environ

    remote.stdout.close()
    remote.stderr.close()


def test_container_signal_targets_node_container(tmp_path):
    remote = make_remote(tmp_path, "ccf:test")
    remote.container_name = "ccf-test-node"
    remote.proc = mock.Mock()
    remote.proc.poll.return_value = None
    completed = subprocess.CompletedProcess([], 0, "", "")

    with (
        mock.patch("infra.remote.shutil.which", return_value="/usr/bin/docker"),
        mock.patch("infra.remote.subprocess.run", return_value=completed) as run,
    ):
        remote._send_signal(signal.SIGTERM)

    run.assert_called_once_with(
        [
            "/usr/bin/docker",
            "kill",
            "--signal",
            "SIGTERM",
            "ccf-test-node",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
