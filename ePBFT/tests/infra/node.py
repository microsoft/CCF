# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
import logging
from loguru import logger
from subprocess import PIPE, Popen
import paramiko


class Node:
    def __init__(
        self, node_id, port, public_key_sig, public_key_enc, private_key, is_replica
    ):
        self.id = node_id
        self.port = port
        self.public_key_sig = public_key_sig
        self.public_key_enc = public_key_enc
        self.private_key = private_key
        self.is_replica = is_replica
        self.client_exe = "client-test"
        self.server_exe = "replica-test"
        self.proc = None
        self.cmd = None

    def set_public_ip(self, p_ip):
        self.public_ip = p_ip

    def set_private_ip(self, p_ip):
        self.private_ip = p_ip

    def set_machine_name(self, machine_name):
        self.machine_name = machine_name

    def set_client_exe(self, client_exe):
        self.client_exe = client_exe

    def set_server_exe(self, server_exe):
        self.server_exe = server_exe

    def node_json(self):
        return {
            "id": int(self.id),
            "port": int(self.port),
            "ip": self.private_ip,
            "pubk_sig": self.public_key_sig,
            "pubk_enc": self.public_key_enc,
            "host_name": self.machine_name,
            "is_replica": self.is_replica,
        }

    def set_cmd(self, cmd):
        self.cmd = cmd


class LocalNode(Node):
    def run(self):
        logger.info(" ".join(self.cmd))
        self.proc = Popen(self.cmd, stdout=True)

    def stop(self):
        logger.info(f"IP: {self.machine_name} - terminating process")
        if self.proc:
            self.proc.terminate()
            self.proc.wait()


class RemoteNode(Node):
    def run(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.public_ip)
        cmd = " ".join(self.cmd)
        logger.info(cmd)
        cmd = f"./{cmd}"
        self.client.exec_command(cmd, get_pty=True)

    def stop(self):
        logger.info(f"IP: {self.machine_name} - terminating process")
        self.client.close()
