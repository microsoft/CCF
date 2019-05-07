# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json
import os
import time
import logging
from contextlib import contextmanager
from glob import glob
import infra.jsonrpc
import infra.remote
import infra.path
import infra.net
import infra.proc
import re

from loguru import logger as LOG

logging.getLogger("paramiko").setLevel(logging.WARNING)


@contextmanager
def network(
    hosts,
    build_directory,
    dbg_nodes=[],
    perf_nodes=[],
    create_nodes=True,
    node_offset=0,
    recovery=False,
    pdb=False,
):
    """
    Context manager for Network class.
    :param hosts: a list of hostnames (localhost or remote hostnames)
    :param build_directory: the build directory
    :param dbg_nodes: default: []. List of node id's that will not start (user is prompted to start them manually)
    :param perf_nodes: default: []. List of node ids that will run under perf record
    :param create_nodes: default: True. If set to false it turns off the automatic node creation
    :return: a Network instance that can be used to create/access nodes, handle the genesis state (add members, create
    node.json), and stop all the nodes that belong to the network
    """
    with infra.path.working_dir(build_directory):
        net = Network(
            hosts=hosts,
            dbg_nodes=dbg_nodes,
            perf_nodes=perf_nodes,
            create_nodes=create_nodes,
            node_offset=node_offset,
            recovery=recovery,
        )
        try:
            yield net
        except Exception:
            if pdb:
                import pdb

                pdb.set_trace()
            else:
                raise
        finally:
            net.stop_all_nodes()


class Network:
    node_args_to_forward = [
        "enclave_type",
        "log_level",
        "expect_quote",
        "sig_max_tx",
        "sig_max_ms",
        "election_timeout",
        "memory_reserve_startup",
        "notify_server",
    ]

    # Maximum delay (seconds) for updates to propagate from the leader to followers
    replication_delay = 30

    def __init__(
        self,
        hosts,
        dbg_nodes=None,
        perf_nodes=None,
        create_nodes=True,
        node_offset=0,
        recovery=False,
    ):
        self.nodes = []
        self.members = []
        self.hosts = hosts
        if create_nodes:
            for node_id, host in enumerate(hosts):
                node_id_ = node_id + node_offset
                self.create_node(
                    node_id_,
                    host,
                    debug=str(node_id_) in (dbg_nodes or []),
                    perf=str(node_id_) in (perf_nodes or []),
                    recovery=recovery,
                )

    def start_and_join(self, args):
        cmd = ["rm", "-f"] + glob("member*.pem")
        infra.proc.ccall(*cmd)

        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        node_status = args.node_status or ["pending"] * len(hosts)
        if len(node_status) != len(hosts):
            raise ValueError("Node statuses are not equal to number of nodes.")

        if not args.package:
            raise ValueError("A package name must be specified.")

        LOG.info("Starting nodes on {}".format(hosts))

        for i, node in enumerate(self.nodes):
            dict_args = vars(args)
            forwarded_args = {
                arg: dict_args[arg] for arg in Network.node_args_to_forward
            }
            node.start(
                lib_name=args.package, node_status=node_status[i], **forwarded_args
            )
        LOG.info("All remotes started")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        self.nodes_json()
        self.add_members([1, 2, 3])
        self.add_users([1, 2, 3])
        self.genesis_generator(args)

        primary = self.nodes[0]
        primary.start_network()

        self.generate_join_rpc(primary)

        for node in self.nodes[1:]:
            node.join_network()

        node_id = 1

        # If there are more than one node in the network, wait until they
        # have joined the network
        for node in self.nodes[1:]:
            if args.wait_with_client:
                with node.management_client() as c:
                    for _ in range(15):
                        id = c.request(method="getCommit", params={})
                        res = c.response(id).result
                        if res[b"commit"] >= 2 and res[b"term"] == 2:
                            LOG.info("Node {} has joined (client)".format(node_id))
                            break
                        time.sleep(1)
                    else:
                        raise ValueError(
                            "Timed out waiting for initial commit on node {}, state was {}".format(
                                node_id, res
                            )
                        )
            else:
                node.wait_until_ready(15)
                LOG.info("Node {} has joined (native client)".format(node_id))
            node_id += 1
        LOG.info("All nodes joined Network")

        return primary, self.nodes[1:]

    def start_in_recovery(self, args, ledger_file, sealed_secrets):
        hosts = self.hosts or ["localhost"] * number_of_local_nodes()

        node_status = args.node_status or ["pending"] * len(hosts)
        if len(node_status) != len(hosts):
            raise ValueError("Node statuses are not equal to number of nodes.")

        if not args.package:
            raise ValueError("A package name must be specified.")

        LOG.info("Starting nodes on {}".format(hosts))

        for i, node in enumerate(self.nodes):
            dict_args = vars(args)
            forwarded_args = {
                arg: dict_args[arg] for arg in Network.node_args_to_forward
            }
            node.start(
                lib_name=args.package,
                node_status=node_status[i],
                ledger_file=ledger_file,
                sealed_secrets=sealed_secrets,
                **forwarded_args,
            )
        LOG.info("All remotes started")

        if args.app_script:
            infra.proc.ccall("cp", args.app_script, args.build_dir).check_returncode()
        if args.gov_script:
            infra.proc.ccall("cp", args.gov_script, args.build_dir).check_returncode()
        LOG.info("Lua scripts copied")

        primary = self.nodes[0]
        return primary, self.nodes[1:]

    def create_node(self, node_id, host, debug=False, perf=False, recovery=False):
        node = Node(node_id, host, debug, perf, recovery)
        self.nodes.append(node)
        return node

    def add_members(self, members):
        self.members.extend(members)
        members = ["member{}".format(m) for m in members]
        for m in members:
            infra.proc.ccall(
                "./genesisgenerator", "cert", "--name={}".format(m)
            ).check_returncode()

    def add_users(self, users):
        users = ["user{}".format(u) for u in users]
        for u in users:
            infra.proc.ccall(
                "./genesisgenerator", "cert", "--name={}".format(u)
            ).check_returncode()

    def genesis_generator(self, args):
        gen = ["./genesisgenerator", "tx"]
        if args.app_script:
            gen.append("--app-script={}".format(args.app_script))
        if args.gov_script:
            gen.append("--gov-script={}".format(args.gov_script))
        infra.proc.ccall(*gen).check_returncode()
        LOG.info("Created Genesis TX")

    def generate_join_rpc(self, node):
        gen = [
            "./genesisgenerator",
            "joinrpc",
            "--host",
            node.host,
            "--port",
            str(node.tls_port),
        ]
        infra.proc.ccall(*gen).check_returncode()
        LOG.info("Created join network RPC")

    def nodes_json(self):
        nodes_json = [node.node_json for node in self.nodes]
        with open("nodes.json", "w") as nodes_:
            json.dump(nodes_json, nodes_, indent=4)
        LOG.info("Created nodes.json")

    def stop_all_nodes(self):
        for node in self.nodes:
            node.stop()
        LOG.info("All remotes stopped...")

    def all_nodes_debug(self):
        for node in self.nodes:
            node.debug = True

    def get_members(self):
        return self.members

    def get_running_nodes(self):
        return [node for node in self.nodes if node.is_stopped() is not True]

    def find_leader(self):
        """
        Find the identity of the leader in the network and return its identity and the current term.
        """
        leader_id = None
        term = None

        for node in self.get_running_nodes():
            with node.management_client() as c:
                id = c.request("getLeaderInfo", {})
                res = c.response(id)
                if res.error is None:
                    leader_id = res.result["leader_id"]
                    term = res.term
                    LOG.error(leader_id)
                    LOG.error(term)
                    break
                else:
                    assert (
                        res.error["code"] == infra.jsonrpc.ErrorCode.TX_LEADER_UNKNOWN
                    ), "RPC error code is not TX_NOT_LEADER"
        assert leader_id is not None, "No leader found"

        return (self.nodes[leader_id], term)


class Checker:
    def __init__(self, management_client=None, notification_queue=None):
        self.management_client = management_client
        self.notification_queue = notification_queue

    def __call__(self, rpc_result, result=None, error=None, timeout=2):
        if error is not None:
            if callable(error):
                assert error(rpc_result.error), rpc_result.error
            else:
                assert rpc_result.error == error, "Expected {}, got {}".format(
                    error, rpc_result.error
                )
            return

        if result is not None:
            if callable(result):
                assert result(rpc_result.result), rpc_result.result
            else:
                assert rpc_result.result == result, "Expected {}, got {}".format(
                    result, rpc_result.result
                )

            if self.management_client:
                for i in range(timeout * 10):
                    r = self.management_client.rpc("getCommit", [rpc_result.commit])
                    if (
                        r.global_commit >= rpc_result.commit
                        and r.result["term"] == rpc_result.term
                    ):
                        return
                    time.sleep(0.1)
                raise TimeoutError("Timed out waiting for commit")

            if self.notification_queue:
                for i in range(timeout * 10):
                    for q in list(self.notification_queue.queue):
                        if json.loads(q)["commit"] >= rpc_result.commit:
                            return
                    time.sleep(0.5)
                raise TimeoutError("Timed out waiting for notification")


class Node:
    def __init__(self, node_id, host, debug=False, perf=False, recovery=False):
        self.node_id = node_id
        self.debug = debug
        self.perf = perf
        self.recovery = recovery
        self.remote = None
        self.node_json = None
        self.stopped = True

        hosts, *port = host.split(":")
        self.host, *self.pubhost = hosts.split(",")
        self.tls_port = port[0] if port else None

        if self.host == "localhost":
            self.host = infra.net.expand_localhost()
            self._set_ports(infra.net.probably_free_local_port)
            self.remote_impl = infra.remote.LocalRemote
        else:
            self._set_ports(infra.net.probably_free_remote_port)
            self.remote_impl = infra.remote.SSHRemote

        self.pubhost = self.pubhost[0] if self.pubhost else self.host

    def _set_ports(self, probably_free_function):
        if self.tls_port is None:
            self.raft_port, self.tls_port = infra.net.two_different(
                probably_free_function, self.host
            )
        else:
            self.raft_port = probably_free_function(self.host)

    def start(self, lib_name, enclave_type="debug", **kwargs):
        """
        Creates a CCFRemote instance, sets it up (connects, creates the directory and ships over the files), and
        (optionally) starts the node by executing the appropriate command.
        If self.debug is set to True, it will not actually start up the node, but will prompt the user to do so manually
        Raises exception if failed to prepare or start the node
        :param lib_name: the enclave package to load
        :param enclave_type: default: debug. Choices: 'simulate', 'debug', 'virtual'
        :return: void
        """
        try:
            lib_path = infra.path.build_lib_path(lib_name, enclave_type)
            self.remote = infra.remote.CCFRemote(
                lib_path,
                str(self.node_id),
                self.host,
                self.pubhost,
                self.raft_port,
                self.tls_port,
                self.remote_impl,
                enclave_type,
                **kwargs,
            )
            self.remote.setup()
            LOG.info("Remote {} started".format(self.node_id))
            self.stopped = False
            if self.recovery:
                self.remote.set_recovery()
            if self.debug:
                print("")
                phost = "localhost" if self.host.startswith("127.") else self.host
                print(
                    "================= Please run the below command on "
                    + phost
                    + " and press enter to continue ================="
                )
                print("")
                print(self.remote.debug_node_cmd())
                print("")
                input("Press Enter to continue...")
                self.node_json = self.remote.info()
            else:
                if self.perf:
                    self.remote.set_perf()
                self.node_json = self.remote.start()
        except Exception:
            LOG.exception("Failed to start node {}".format(self.host))
            raise

    def stop(self):
        if self.remote:
            self.remote.stop()
            self.stopped = True

    def is_stopped(self):
        return self.stopped

    def start_network(self):
        infra.proc.ccall(
            "./client",
            "--host={}".format(self.host),
            "--port={}".format(self.tls_port),
            "--ca={}".format(self.remote.pem),
            "startnetwork",
        ).check_returncode()
        LOG.info("Started Network")

    def join_network(self):
        infra.proc.ccall(
            "./client",
            "--host={}".format(self.host),
            "--port={}".format(self.tls_port),
            "--ca={}".format(self.remote.pem),
            "joinnetwork",
            "--req=joinNetwork.json",
        ).check_returncode()
        LOG.info("Joining Network")

    def set_recovery(self):
        self.remote.set_recovery()

    def restart(self):
        self.remote.restart()

    def get_sealed_secrets(self):
        return self.remote.get_sealed_secrets()

    def wait_until_ready(self, timeout=5):
        with open("getCommit.json", "w") as gcf:
            gcf.write('{"id":1,"jsonrpc":"2.0","method":"getCommit","params":{}}\n')
        for _ in range(timeout):
            time.sleep(1)
            rv = infra.proc.ccall(
                "./client",
                "--host={}".format(self.host),
                "--port={}".format(self.tls_port),
                "--ca=networkcert.pem",
                "userrpc",
                "--cert=user1_cert.pem",
                "--pk=user1_privk.pem",
                "--req=getCommit.json",
                log_output=False,
            )
            # Make sure that the commit is greater than 2
            if re.search(r'"commit":([2-9]|\d{2,})', rv.stdout.decode()):
                return
        raise ValueError("Timed out waiting for node {}".format(self.node_id))

    def user_client(self, format="msgpack", user_id=1, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.tls_port,
            cert="user{}_cert.pem".format(user_id),
            key="user{}_privk.pem".format(user_id),
            cafile="networkcert.pem",
            description="node {} (user)".format(self.node_id),
            format=format,
            **kwargs,
        )

    def management_client(self, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.tls_port,
            "management",
            cert=None,
            key=None,
            description="node {} (mgmt)".format(self.node_id),
            **kwargs,
        )

    def member_client(self, member_id=1, **kwargs):
        return infra.jsonrpc.client(
            self.host,
            self.tls_port,
            "members",
            cert="member{}_cert.pem".format(member_id),
            key="member{}_privk.pem".format(member_id),
            cafile="networkcert.pem",
            description="node {} (member)".format(self.node_id),
            **kwargs,
        )
