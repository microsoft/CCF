Proposing and Voting for a Proposal
===================================

This page explains how members can submit and vote for proposals.

Proposals and vote ballots are submitted as Lua scripts. These scripts are executed transactionally, able to read from the current KV state but not write directly to it. Proposals return a list of proposed actions which can make writes, but are only applied when the proposal is accepted. Each vote script is given this list of proposed actions, and also able to read from the KV, and returns a boolean indicating whether it supports or rejects the proposed actions.

Any member can submit a new proposal. All members can then vote on this proposal using its unique proposal id.
Each member may alter their vote (by submitting a new vote) any number of times while the proposal is open.
The proposer has the ability to `withdraw` a proposal while it is open.

Each time a vote is submitted, all vote ballots for this proposal are re-executed on the current state to determine whether they are `for` or `against` the proposal. This vote tally is passed to the :term:`Constitution`, which determines whether the proposal is accepted or remains open. Once a proposal is accepted under the rules of the :term:`Constitution`, it is executed and its effects are recorded in the ledger.

For transparency and auditability, all governance operations (including votes) are recorded in plaintext in the ledger and members are required to sign their requests.

Creating a Proposal
-------------------

For custom proposals with multiple actions and precise conditional requirements you will need to write the proposal script by hand. For simple proposals there is a helper script in the CCF Python package - `proposal_generator.py`. This can be used to create proposals for common operations like adding members and users, without writing any Lua. It also produces sample vote scripts, which validate that the executed proposed actions exactly match what is expected. These sample proposals and votes can be used as a syntax and API reference for producing more complex custom proposals.

Assuming the CCF Python package has been installed in the current Python environment, the proposal generator can be invoked directly as ``ccf.proposal_generator``. With no further argument it will print help text, including the list of possible actions as subcommands:

.. code-block:: bash

    $ python -m ccf.proposal_generator
    usage: proposal_generator.py [-h] [-po PROPOSAL_OUTPUT_FILE] [-vo VOTE_OUTPUT_FILE] [-pp] [-i] [-v]
                             {accept_recovery,new_member,new_node_code,new_user,open_network,rekey_ledger,remove_user,retire_member,retire_node,set_js_app,set_lua_app,set_recovery_threshold,set_user_data,trust_node,update_recovery_shares}

Additional detail is available from the ``--help`` option. You can also find the script in a checkout of CCF:

.. code-block:: bash

    $ python CCF/python/ccf/proposal_generator.py

Some of these subcommands require additional arguments, such as the node ID or user certificate to add to the service. Additional options allow the generated votes and proposals to be redirected to other files or pretty-printed:

.. code-block:: bash

    $ python -m ccf.proposal_generator trust_node 5
    SUCCESS | Writing proposal to ./trust_node_proposal.json
    SUCCESS | Wrote vote to ./trust_node_vote_for.json

    $ cat trust_node_proposal.json
    {"script": {"text": "tables, args = ...; return Calls:call(\"trust_node\", args)"}, "parameter": "5"}

    $ cat trust_node_vote_for.json
    {"ballot": {"text": "tables, calls = ...; if not #calls == 1 then return false end; call = calls[1]; if not call.func == \"trust_node\" then return false end; args = call.args; if args == nil then return false end; if not args == [====[5]====] then return false end; return true"}}

    $ python -m ccf.proposal_generator --pretty-print --proposal-output-file add_pedro.json --vote-output-file vote_for_pedro.json new_user pedro_cert.pem
    SUCCESS | Writing proposal to ./add_pedro.json
    SUCCESS | Wrote vote to ./vote_for_pedro.json

    $ cat add_pedro.json
    {
      "script": {
        "text": "tables, args = ...; return Calls:call(\"new_user\", args)"
      },
      "parameter": "-----BEGIN CERTIFICATE-----\nMIIBrzCCATSgAwIBAgIUJY+H0OzuFQWz/udd+WCD7Cv+cgwwCgYIKoZIzj0EAwMw\nDjEMMAoGA1UEAwwDYm9iMB4XDTIwMDcyNDE1MzYyOFoXDTIxMDcyNDE1MzYyOFow\nDjEMMAoGA1UEAwwDYm9iMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7h75Xd1+0QDD\nWF2edGphgryHcDoBXdRowq6ciYH2++ilXXagi5Rybai7ewgV0YuvrDm+WfGyJ9CC\n5HbT6C/z5GCJQnLH2t3LaZrw9MQDF3bH6XOHGmaJh6m7rfpZZljpo1MwUTAdBgNV\nHQ4EFgQUN/LhCyVExERjt5f1RZx7820934wwHwYDVR0jBBgwFoAUN/LhCyVExERj\nt5f1RZx7820934wwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEA\n5MsDNvjEMSgYXy+bPbE2nxOlmH6OhP375IVZxNQALJGzTfgHu+IbpyvDF0/VrMrW\nAjEA723VxgMgpuxB5SszN6eZuz8EW51DsgRIVWMSbBZYYBYyQmu5x3T+Hx/Cs7TD\nu4Ee\n-----END CERTIFICATE-----\n"
    }

    $ cat vote_for_pedro.json
    {
      "ballot": {
        "text": "tables, calls = ...; if not #calls == 1 then return false end; call = calls[1]; if not call.func == \"new_user\" then return false end; args = call.args; if args == nil then return false end; if not args == [====[-----BEGIN CERTIFICATE-----\nMIIBrzCCATSgAwIBAgIUJY+H0OzuFQWz/udd+WCD7Cv+cgwwCgYIKoZIzj0EAwMw\nDjEMMAoGA1UEAwwDYm9iMB4XDTIwMDcyNDE1MzYyOFoXDTIxMDcyNDE1MzYyOFow\nDjEMMAoGA1UEAwwDYm9iMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7h75Xd1+0QDD\nWF2edGphgryHcDoBXdRowq6ciYH2++ilXXagi5Rybai7ewgV0YuvrDm+WfGyJ9CC\n5HbT6C/z5GCJQnLH2t3LaZrw9MQDF3bH6XOHGmaJh6m7rfpZZljpo1MwUTAdBgNV\nHQ4EFgQUN/LhCyVExERjt5f1RZx7820934wwHwYDVR0jBBgwFoAUN/LhCyVExERj\nt5f1RZx7820934wwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEA\n5MsDNvjEMSgYXy+bPbE2nxOlmH6OhP375IVZxNQALJGzTfgHu+IbpyvDF0/VrMrW\nAjEA723VxgMgpuxB5SszN6eZuz8EW51DsgRIVWMSbBZYYBYyQmu5x3T+Hx/Cs7TD\nu4Ee\n-----END CERTIFICATE-----\n]====] then return false end; return true"
      }
    }

These proposals and votes should be sent as the body of HTTP requests as described below.

Creating Proposals in Python
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``ccf.proposal_generator`` can also be imported and used in a Python application instead of as a command-line tool.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: import_proposal_generator
    :lines: 1

The proposal generation functions return dictionaries that can be submitted to a ``CCFClient``.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: dict_proposal
    :end-before: SNIPPET_END: dict_proposal

You may wish to write these proposals to files so they can be examined or modified further. These proposal files can be submitted directly --- ``CCFClient`` will treat string request bodies beginning with an ``@`` as file paths in the same way that ``curl`` does, and use the content of the file when sending.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: json_proposal_with_file
    :end-before: SNIPPET_END: json_proposal_with_file

Submitting a New Proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using ``POST /gov/proposals`` and vote using ``POST /gov/proposals/{proposal_id}/votes``.

For example, ``member1`` may submit a proposal to add a new member (``member4``) to the consortium:

.. code-block:: bash

    $ cat new_member.json
    {
      "parameter": {
        "cert": "-----BEGIN CERTIFICATE-----\nMIIBdzCCARygAwIBAgIURwD6S1/rcb2TbHhQLnTNh/7WyYYwCgYIKoZIzj0EAwIw\nEjEQMA4GA1UEAwwHbWVtYmVyNDAeFw0yMDEwMjkxNjI2NTNaFw0yMTEwMjkxNjI2\nNTNaMBIxEDAOBgNVBAMMB21lbWJlcjQwVjAQBgcqhkjOPQIBBgUrgQQACgNCAARG\nwqj2ZD7vA+h4KoTdh3if3tVO/yks+xtLU1tXAFsbeWSQfDxK3nnA65uX6n/25A20\nJcAQMDHYH2NdLOLra9lxo1MwUTAdBgNVHQ4EFgQUQQDC71N60r/a9c+EGXrzr5l6\nIDQwHwYDVR0jBBgwFoAUQQDC71N60r/a9c+EGXrzr5l6IDQwDwYDVR0TAQH/BAUw\nAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAkvP0AuAU7y0b3z4rhvoOkCBKoH4G3vh/\nPJpLFdWcEu4CIQCSnEYpDaDTP2zoWTheqchZ+/BdTzM2j2s9ILpvSVYMxg==\n-----END CERTIFICATE-----\n",
        "encryption_pub_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvYKesV5xoT2XnGhLkeqZ\neSC2KsjNUvdjqPrTERk/hp64Xd30SGjdj2HytG3hfCy5hBhc9muQMXoOAOBgxwMA\nQRu7KCANPZNCLEWKR5DZc8YzE+rHX1/8WxhhtV/bvr90selV0BfLWLLJYDxnyo3D\nyioYXNw6Ij2sYBt8MTPNPti3jRJ7LmMow/VrJD9Ww1FKWCyxa7/iCxSsbmrwdv8m\nBVf/+d3p+ivxb6gBvtTimj+fj1OdRkGHElZSaBFWmQISga3Ki4vnP4W1iw/ujaza\n3gItLPrEnD0lxGBaCSs+XVm2l8nsn3HJDZYMP5u3jWB3MWsBwna0o+KUon4KaS1k\nlwIDAQAB\n-----END PUBLIC KEY-----\n",
        "member_data": null
      },
      "script": {
        "text": "\n    tables, args = ...\n    return Calls:call(\"new_member\", args)\n    "
      }
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member1_privk --cert member1_cert --data-binary @add_member.json -H "content-type: application/json"
    {
      "proposal_id": 4,
      "proposer_id": 1,
      "state": "OPEN"
    }

In this case, a new proposal with id ``4`` has successfully been created and the proposer member has voted to accept it (they may instead pass a voting ballot with their proposal if they wish to vote conditionally, or withhold their vote until later). Other members can then vote to accept or reject the proposal:

.. code-block:: bash

    # Proposal 4 already exists, and has a single vote in favour from the proposer member 1 (votes in favour: 1/3)

    $ cat vote_reject.json
    {
        "ballot": {
            "text": "return false"
        }
    }

    $ cat vote_accept.json
    {
        "ballot": {
            "text": "return true"
        }
    }

    # Member 2 rejects the proposal (votes in favour: 1/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/4/votes --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_reject.json -H "content-type: application/json"
    {
      "proposal_id": 4,
      "proposer_id": 1,
      "state": "OPEN"
    }

    # Member 3 accepts the proposal (votes in favour: 2/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/4/votes --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
      "proposal_id": 4,
      "proposer_id": 1,
      "state": "ACCEPTED"
    }

    # As a majority of members have accepted the proposal, member 4 is added to the consortium

As soon as ``member3`` accepts the proposal, a majority (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active by sending a ``members/ack`` request, signing their current nonce. See :ref:`members/adding_member:Activating a New Member`.

Displaying Proposals
--------------------

The details of pending proposals, including the proposer member id, proposal script, parameters, and votes, can be queried from the service by calling ``GET /gov/proposals/{proposal_id}``. For example, after accepting the proposal above:

.. code-block:: bash

    # The full proposal state, including votes, can still be retrieved by any member
    $ scurl.sh https://<ccf-node-address>/gov/proposals/4 --cacert networkcert.pem --key member3_privk.pem --cert member3_cert.pem -H "content-type: application/json" -X GET
    {
      "parameter": {...},
      "proposer": 1,
      "script": {...},
      "state": "ACCEPTED",
      "votes": [
        [
          1,
          {
            "text": "return true"
          }
        ],
        [
          2,
          {
            "text": "return true"
          }
        ],
        [
          3,
          {
            "text": "return false"
          }
        ]
      ]
    }

Withdrawing a Proposal
----------------------

At any stage during the voting process, before the proposal is accepted, the proposing member may decide to withdraw a pending proposal:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals/<proposal-id>/withdraw --cacert networkcert.pem --key member1_privk.pem --cert member1_cert.pem -H "content-type: application/json"
    {
      "proposal_id": 4,
      "proposer_id": 1,
      "state": "WITHDRAWN"
    }

This means future votes will be rejected, and the proposal will never be accepted. However it remains visible as a proposal so members can easily audit historic proposals.
