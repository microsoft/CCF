# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
import infra.proc

import e2e_args
import getpass
import os
import time
import logging
import multiprocessing
from random import seed
import infra.ccf
import infra.proc
import infra.jsonrpc
import json

from loguru import logger as LOG


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        # create a lua query file to change a member state to accepted
        with open("query.lua", "w") as qfile:
            qfile.write(
                """local tables, param = ...
               local member_id = param
               local STATE_ACCEPTED = 0
               local member_info = {status = STATE_ACCEPTED}
               local p = Puts:new()
               p:put("members", member_id, member_info)
               return Calls:call("raw_puts", p)"""
            )

        # create json file to be passed as the argument to the query.lua file
        # it is passing a member id
        with open("param.json", "w") as pfile:
            pfile.write("""{"p": 0}""")

        # propose to add a new member
        # proposal number 0
        infra.proc.ccall("./genesisgenerator", "cert", "--name=member4")
        result = infra.proc.ccall(
            "./memberclient",
            "add_member",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--member_cert=member4_cert.pem",
            "--ca=networkcert.pem",
        )
        # when proposal is added the proposal id and the result of running complete proposal are returned
        j_result = json.loads(result.stdout)
        assert not j_result["result"]["completed"]
        assert j_result["result"]["id"] == 0

        # display all proposals
        infra.proc.ccall(
            "./memberclient",
            "proposal_display",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--ca=networkcert.pem",
        )

        # 2 out of 3 members vote to accept the new member so that that member can send its own proposals
        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
            "--sign",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]

        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member2_cert.pem",
            "--privk=member2_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
            "--sign",
        )
        j_result = json.loads(result.stdout)
        assert j_result["result"]

        # member 4 try to make a proposal without having been accepted should get insufficient rights response
        result = infra.proc.ccall(
            "./memberclient",
            "accept_node",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
        )  # id here is node id
        j_result = json.loads(result.stdout)
        assert (
            j_result["error"]["code"]
            == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value
        )

        # member 4 ack
        result = infra.proc.ccall(
            "./memberclient",
            "ack",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert j_result["result"]

        # member 4 is now active and sends an accept node proposal
        # proposal number 1
        result = infra.proc.ccall(
            "./memberclient",
            "accept_node",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
        )  # id here is node id
        j_result = json.loads(result.stdout)
        assert not j_result["result"]["completed"]
        assert j_result["result"]["id"] == 1

        # members vote to accept the node proposal
        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=1",
            "--ca=networkcert.pem",
            "--sign",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]

        # result is true with just 2 votes because proposer implicit pro vote is assumed
        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member2_cert.pem",
            "--privk=member2_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=1",
            "--ca=networkcert.pem",
            "--sign",
        )
        j_result = json.loads(result.stdout)
        assert j_result["result"]

        # member 4 is makes a proposal and then removes it
        # proposal number 2
        result = infra.proc.ccall(
            "./memberclient",
            "accept_node",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=1",
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]["completed"]
        assert j_result["result"]["id"] == 2

        result = infra.proc.ccall(
            "./memberclient",
            "removal",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=2",
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert j_result["result"]

        # member 4 proposes to inactivate member 1 and other members vote yes
        # proposal number 3
        result = infra.proc.ccall(
            "./memberclient",
            "raw_puts",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--script=query.lua",
            "--param=param.json",
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]["completed"]
        assert j_result["result"]["id"] == 3

        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member3_cert.pem",
            "--privk=member3_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=3",
            "--ca=networkcert.pem",
            "--sign",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]

        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member2_cert.pem",
            "--privk=member2_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=3",
            "--ca=networkcert.pem",
            "--sign",
        )
        j_result = json.loads(result.stdout)
        assert j_result["result"]

        # member 1 attempts to accept a proposal but should get insufficient rights
        # proposal number 4
        result = infra.proc.ccall(
            "./memberclient",
            "accept_node",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
        )  # id here is node id
        j_result = json.loads(result.stdout)
        assert (
            j_result["error"]["code"]
            == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value
        )

        # member 4 proposes to add member 3 as user
        result = infra.proc.ccall(
            "./memberclient",
            "add_user",
            "--cert=member4_cert.pem",
            "--privk=member4_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--user_cert=member3_cert.pem",
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]["completed"]


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libloggingenc)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)
    run(args)
