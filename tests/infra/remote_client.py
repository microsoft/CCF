# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import time
import paramiko
import logging
import getpass
from contextlib import contextmanager
import infra.remote
from glob import glob

from loguru import logger as LOG

DBG = os.getenv("DBG", "cgdb")


class CCFRemoteClient(object):
    BIN = "cchost"
    DEPS = []

    def __init__(
        self,
        name,
        host,
        bin_path,
        node_host,
        node_port,
        workspace,
        label,
        iterations,
        config,
        command_args,
        remote_class,
    ):
        """
        Creates a ccf client on a remote host.
        """
        self.host = host
        self.name = name
        self.BIN = infra.path.build_bin_path(bin_path)

        # strip out the config from the path

        self.DEPS = glob("*.pem") + [config]

        if "--verify" in command_args:
            # append verify file to the files to be copied
            # and fix the path in the argument list
            v_index = command_args.index("--verify")
            verify_path = command_args[v_index + 1]
            self.DEPS += [verify_path]
            command_args[v_index + 1] = os.path.basename(verify_path)

        cmd = [
            self.BIN,
            "--host={}".format(node_host),
            "--port={}".format(node_port),
            "--transactions={}".format(iterations),
            "--config={}".format(os.path.basename(config)),
        ] + command_args

        self.remote = remote_class(
            name, host, [self.BIN] + self.DEPS, cmd, workspace, label
        )

    def setup(self):
        self.remote.setup()
        LOG.success(f"Remote client {self.name} setup")

    def start(self):
        self.remote.start()

    def restart(self):
        self.remote.restart()

    def node_cmd(self):
        return self.remote._cmd()

    def debug_node_cmd(self):
        return self.remote._dbg()

    def stop(self, retrieve_csvs=False):
        try:
            self.remote.stop()
            if retrieve_csvs:
                remote_files = self.remote.list_files()
                remote_csvs = [f for f in remote_files if f.endswith(".csv")]
                for csv in remote_csvs:
                    if csv == "perf_summary.csv":
                        remote_perf = "{}_perf_summary.csv".format(self.name)
                        self.remote.get(csv, 1, remote_perf)
                        with open("perf_summary.csv", "a") as l:
                            with open(remote_perf, "r") as r:
                                for line in r.readlines():
                                    l.write(line)
                    else:
                        self.remote.get(csv, 1)
        except Exception:
            LOG.exception("Failed to shut down {} cleanly".format(self.name))

    def wait(self):
        try:
            self.remote.wait_for_stdout_line(line="Global commit", timeout=5)
        except Exception:
            LOG.exception("Failed to wait on client {}".format(self.name))
