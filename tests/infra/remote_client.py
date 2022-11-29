# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import infra.network
import infra.remote

from loguru import logger as LOG

DBG = os.getenv("DBG", "cgdb")


class CCFRemoteClient(object):
    DEPS = []
    LINES_RESULT_FROM_END = 8

    def __init__(
        self,
        name,
        host,
        bin_path,
        node_host,
        node_port,
        workspace,
        label,
        config,
        command_args,
        remote_class,
        piccolo_run=False,
    ):
        """
        Creates a ccf client on a remote host.
        """
        self.host = host
        self.name = name
        self.BIN = infra.path.build_bin_path(bin_path)

        # strip out the config from the path
        self.common_dir = infra.network.get_common_folder_name(workspace, label)

        self.DEPS = [
            os.path.join(self.common_dir, "user1_cert.pem"),
            os.path.join(self.common_dir, "user1_privk.pem"),
            os.path.join(self.common_dir, "service_cert.pem"),
        ] + [config]
        client_command_args = list(command_args)

        if "--verify" in client_command_args:
            # append verify file to the files to be copied
            # and fix the path in the argument list
            v_index = client_command_args.index("--verify")
            verify_path = client_command_args[v_index + 1]
            self.DEPS += [verify_path]
            client_command_args[v_index + 1] = os.path.basename(verify_path)

        if piccolo_run:
            cmd = [
                self.BIN,
                f"--server-address={node_host}:{node_port}",
            ] + client_command_args
        else:
            cmd = [
                self.BIN,
                f"--rpc-address={node_host}:{node_port}",
                f"--config={os.path.basename(config)}",
            ] + client_command_args

        self.remote = remote_class(
            name, host, [self.BIN], self.DEPS, cmd, workspace, self.common_dir
        )

    def setup(self):
        self.remote.setup()
        LOG.success(f"Remote client {self.name} setup")

    def start(self):
        self.remote.start()

    def debug_node_cmd(self):
        return self.remote.debug_node_cmd()

    def stop(self):
        self.remote.stop()
        remote_files = self.remote.list_files()
        remote_csvs = [f for f in remote_files if f.endswith(".csv")]

        for csv in remote_csvs:
            remote_file_dst = f"{self.name}_{csv}"
            self.remote.get(csv, self.common_dir, 1, remote_file_dst)
            if csv == "perf_summary.csv":
                with open("perf_summary.csv", "a", encoding="utf-8") as l:
                    with open(
                        os.path.join(self.common_dir, remote_file_dst),
                        "r",
                        encoding="utf-8",
                    ) as r:
                        l.write(r.read())

    def check_done(self):
        return self.remote.check_done()

    def get_result(self):
        return self.remote.get_result(self.LINES_RESULT_FROM_END)
