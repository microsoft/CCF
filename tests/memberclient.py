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
        result = network.propose(
            "add_member", "--member_cert=member4_cert.pem", 1, primary
        )

        # when proposal is added the proposal id and the result of running complete proposal are returned
        proposal_id = result[1]["id"]
        assert not result[1]["completed"]
        assert proposal_id == 0

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
        result = network.vote(0, True, 1, primary)
        assert not result

        result = network.vote(0, True, 2, primary)
        assert result

        # member 4 try to make a proposal without having been accepted should get insufficient rights response
        result = network.propose("accept_node", "--id=0", 4, primary)
        assert result[1] == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value

        # member 4 ack
        j_result = network.member_client_rpc(4, primary, "ack")
        assert j_result["result"]

        # member 4 is now active and sends an accept node proposal
        # proposal number 1
        result = network.propose("accept_node", "--id=0", 4, primary)
        assert not result[1]["completed"]
        proposal_id = result[1]["id"]
        assert proposal_id == 1

        # members vote to accept the node proposal
        result = network.vote(proposal_id, True, 1, primary)
        assert not result

        # result is true with just 2 votes because proposer implicit pro vote is assumed
        result = network.vote(proposal_id, True, 2, primary)
        assert j_result

        # member 4 is makes a proposal and then removes it
        # proposal number 2
        result = network.propose("accept_node", "--id=1", 4, primary)
        proposal_id = result[1]["id"]
        assert not result[1]["completed"]
        assert proposal_id == 2

        j_result = network.member_client_rpc(4, primary, "removal", "--id=2")
        assert j_result["result"]

        # member 4 proposes to inactivate member 1 and other members vote yes
        # proposal number 3
        j_result = network.member_client_rpc(
            4,
            primary,
            "raw_puts",
            "raw_puts",
            "--script=query.lua",
            "--param=param.json",
        )
        assert not j_result["result"]["completed"]
        assert j_result["result"]["id"] == 3

        result = network.vote(3, True, 3, primary)
        assert not result

        result = network.vote(3, True, 2, primary)
        assert j_result

        # member 1 attempts to accept a proposal but should get insufficient rights
        # proposal number 4
        result = network.propose("accept_node", "--id=0", 1, primary)
        assert result[1] == infra.jsonrpc.ErrorCode.INSUFFICIENT_RIGHTS.value

        # member 4 proposes to add member 3 as user
        result = network.propose("add_user", "--user_cert=member3_cert.pem", 4, primary)
        assert not result[1]["completed"]


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
