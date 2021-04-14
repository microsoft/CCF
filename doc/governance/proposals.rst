Proposing and Voting for a Proposal
===================================

.. warning::
    This page describes the deprecated Lua constitution.
    These docs will be replaced shortly to describe the new JS constitution.
    See :doc:`/governance/js_gov` for pointers on converting from Lua to JS.

This page explains how members can submit and vote for proposals.

Proposals and vote ballots are submitted as Lua scripts. These scripts are executed transactionally, able to read from the current KV state but not write directly to it. Proposals return a list of proposed actions which can make writes, but are only applied when the proposal is accepted. Each vote script is given this list of proposed actions, and also able to read from the KV, and returns a Boolean indicating whether it supports or rejects the proposed actions.

Any member can submit a new proposal. All members can then vote, once at most, on this proposal using its unique proposal id.
The proposer has the ability to `withdraw` a proposal while it is open.

Each time a vote is submitted, all vote ballots for this proposal are re-executed on the current state to determine whether they are `for` or `against` the proposal. This vote tally is passed to the :term:`Constitution`, which determines whether the proposal is accepted or remains open. Once a proposal is accepted under the rules of the :term:`Constitution`, it is executed and its effects are recorded in the ledger.

For transparency and auditability, all governance operations (including votes) are recorded in plaintext in the ledger and members are required to sign their requests.

Creating a Proposal
-------------------

For custom proposals with multiple actions and precise conditional requirements you will need to write the proposal script by hand. For simple proposals there is a helper script in the CCF Python package - `proposal_generator.py`. This can be used to create proposals for common operations like adding members and users, without writing any Lua. It also produces sample vote scripts, which validate that the executed proposed actions exactly match what is expected. These sample proposals and votes can be used as a syntax and API reference for producing more complex custom proposals.

Assuming the CCF Python package has been installed in the current Python environment, the proposal generator can be invoked directly as ``ccf.proposal_generator``. With no further argument it will print help text, including the list of possible actions as subcommands:

.. code-block:: bash

    python -m ccf.proposal_generator
    usage: proposal_generator.py [-h] [-po PROPOSAL_OUTPUT_FILE] [-vo VOTE_OUTPUT_FILE] [-pp] [-i] [-v]
                             {new_member,new_node_code,set_user,rekey_ledger,remove_ca_cert_bundle,remove_js_app,remove_jwt_issuer,remove_member,remove_user,retire_node,retire_node_code,set_ca_cert_bundle,set_js_app,set_jwt_issuer,set_jwt_public_signing_keys,set_member_data,set_recovery_threshold,set_user_data,transition_service_to_open,trust_node,update_recovery_shares}

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
    {
      "ballot": "export function vote (rawProposal, proposerId) {\n  let proposal = JSON.parse(rawProposal);\n  if (!('actions' in proposal)) { return false; };\n  let actions = proposal['actions'];\n  if (actions.length !== 1) { return false; };\n  let action = actions[0];\n  if (!('name' in action)) { return false; };\n  if (action.name !== 'transition_node_to_trusted') { return false; };\n  if (!('args' in action)) { return false; };\n  let args = action.args;\n  {\n    if (!('node_id' in args)) { return false; };\n    let expected = \"cc6e776911230e4c419475b528ae272c655b1133c513476783daea67c59d9ffa\";\n    if (JSON.stringify(args['node_id']) !== JSON.stringify(expected)) { return false; };\n  }\n  return true;\n}"
    }

    $ python -m ccf.proposal_generator --pretty-print --proposal-output-file add_pedro.json --vote-output-file vote_for_pedro.json set_user pedro_cert.pem
    SUCCESS | Writing proposal to ./add_pedro.json
    SUCCESS | Wrote vote to ./vote_for_pedro.json

    $ cat add_pedro.json
    {
      "actions": [
        {
          "name": "set_user",
          "args": {
            "cert": "-----BEGIN CERTIFICATE-----\nMIIBsjCCATigAwIBAgIUOiTU32JZsA0dSv64hW2mrKM0phEwCgYIKoZIzj0EAwMw\nEDEOMAwGA1UEAwwFdXNlcjIwHhcNMjEwNDE0MTUyODMyWhcNMjIwNDE0MTUyODMy\nWjAQMQ4wDAYDVQQDDAV1c2VyMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABBFf+FD0\nUGIyJubt8j+f8+/BP7IY6G144yF/vBNe7CJpNNRyiMZzEyN6wmEKIjsn3gU36A6E\nqNYBlbYbXD1kzlw4q/Pe/Wl3o237p8Es6LD1e1MDUFp2qUcNA6vari6QLKNTMFEw\nHQYDVR0OBBYEFDuGVragGSHoIrFA44kQRg/SKIcFMB8GA1UdIwQYMBaAFDuGVrag\nGSHoIrFA44kQRg/SKIcFMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaAAw\nZQIxAPx54LaqQevKrcZIr7QSCZKGFJgSxfVxovSfEqTMD+sKdWzNTqJtJ1SDav1v\nImA4iwIwBsrdevSQj4U2ynXiTJKljviDnyc47ktJVkg/Ppq5cMcEZHO4Q0H/Wq3H\nlUuVImyR\n-----END CERTIFICATE-----\n"
          }
        }
      ]
    }

    $ cat vote_for_pedro.json
    {
      "ballot": "export function vote (rawProposal, proposerId) {\n  let proposal = JSON.parse(rawProposal);\n  if (!('actions' in proposal)) { return false; };\n  let actions = proposal['actions'];\n  if (actions.length !== 1) { return false; };\n  let action = actions[0];\n  if (!('name' in action)) { return false; };\n  if (action.name !== 'set_user') { return false; };\n  if (!('args' in action)) { return false; };\n  let args = action.args;\n  {\n    if (!('cert' in args)) { return false; };\n    let expected = \"-----BEGIN CERTIFICATE-----\\nMIIBsjCCATigAwIBAgIUOiTU32JZsA0dSv64hW2mrKM0phEwCgYIKoZIzj0EAwMw\\nEDEOMAwGA1UEAwwFdXNlcjIwHhcNMjEwNDE0MTUyODMyWhcNMjIwNDE0MTUyODMy\\nWjAQMQ4wDAYDVQQDDAV1c2VyMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABBFf+FD0\\nUGIyJubt8j+f8+/BP7IY6G144yF/vBNe7CJpNNRyiMZzEyN6wmEKIjsn3gU36A6E\\nqNYBlbYbXD1kzlw4q/Pe/Wl3o237p8Es6LD1e1MDUFp2qUcNA6vari6QLKNTMFEw\\nHQYDVR0OBBYEFDuGVragGSHoIrFA44kQRg/SKIcFMB8GA1UdIwQYMBaAFDuGVrag\\nGSHoIrFA44kQRg/SKIcFMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaAAw\\nZQIxAPx54LaqQevKrcZIr7QSCZKGFJgSxfVxovSfEqTMD+sKdWzNTqJtJ1SDav1v\\nImA4iwIwBsrdevSQj4U2ynXiTJKljviDnyc47ktJVkg/Ppq5cMcEZHO4Q0H/Wq3H\\nlUuVImyR\\n-----END CERTIFICATE-----\\n\";\n    if (JSON.stringify(args['cert']) !== JSON.stringify(expected)) { return false; };\n  }\n  return true;\n}"
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

    $ cat set_member.json
    {
      "actions": [
        {
          "name": "set_member",
          "args": {
            "cert": "-----BEGIN CERTIFICATE-----\nMIIBeDCCAR+gAwIBAgIUNIlSzogSRYEIFzXZkt/8+yPP1mkwCgYIKoZIzj0EAwIw\nEjEQMA4GA1UEAwwHbWVtYmVyNTAeFw0yMTA0MTQxNTI5MDdaFw0yMjA0MTQxNTI5\nMDdaMBIxEDAOBgNVBAMMB21lbWJlcjUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAATQ31dh+lbI9wtmEA5B9uvwMpchayuC6y2ODpvdikpW22YEEgMOHRTz9C1ouyA6\nDU/B8e44/Ix8EOyZ/o+o/x4uo1MwUTAdBgNVHQ4EFgQUkw5qTP11HKXElw/1PgS9\nczAI6kwwHwYDVR0jBBgwFoAUkw5qTP11HKXElw/1PgS9czAI6kwwDwYDVR0TAQH/\nBAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBKK27btVObhaY3dNaRfTE5EPZeUvFQ\nysnx5xOcn7MGIAIgErGPvJeOD1mVKnHIsJ7JWpxbHCOWkiWuX5uPIX8didQ=\n-----END CERTIFICATE-----\n",
            "encryption_pub_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHGQBecZimsPBmDJP7Bb\nSEtn3n2ee8luvyYWDgmxH2+GCE9bBdDrRu4qibGk/itrJ0ezIXChdszTQk1MdG0a\noWa4LbV2wTT7wRaqla+QaVI0VUAFFWuZkRlrTNvD6rizB7YBC9Qy54FqSmWfqbyK\nZF4gsnODPo78CABuiGvqASKfi9cfhJYARsXwFQNDTj+M9gXzThwC+oT5etOHmLVX\nxrs4mEmKaVgRS/qjedqqq2WSseteWDTg72LuSUgxC3OMBD+E0xQfOAOBXsi7EVqv\naPLlDSQJBG5tQDltz+kspUs3WWcP0UMY/mCvWeFtpP2wcaH5Y60PdYeOnSDYfCB5\nKwIDAQAB\n-----END PUBLIC KEY-----\n"
          }
        }
      ]
    }

    $ scurl.sh https://<ccf-node-address>/gov/proposals.js --cacert network_cert --key member1_privk --cert member1_cert --data-binary @add_member.json -H "content-type: application/json"
    {
      "ballot_count": 0,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

In this case, a new proposal with id ``4`` has successfully been created and the proposer member has voted to accept it (they may instead pass a voting ballot with their proposal if they wish to vote conditionally, or withhold their vote until later). Other members can then vote to accept or reject the proposal:

.. code-block:: bash

    # Proposal 4 already exists, and has a single vote in favour from the proposer member 1 (votes in favour: 1/3)

    $ cat vote_reject.json
    {
      "ballot": "export function vote (proposal, proposerId) { return false }"
    }

    $ cat vote_accept.json
    {
      "ballot": "export function vote (proposal, proposerId) { return true }"
    }

    # Member 2 rejects the proposal (votes in favour: 1/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals.js/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/votes --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_reject.json -H "content-type: application/json"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

    # Member 3 accepts the proposal (votes in favour: 2/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/votes --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
      "ballot_count": 2,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Accepted"
    }

    # As a majority of members have accepted the proposal, member 4 is added to the consortium

As soon as ``member3`` accepts the proposal, a majority (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active by sending a ``/gov/ack`` request. See :ref:`governance/adding_member:Activating a New Member`.

Displaying Proposals
--------------------

The details of pending proposals, including the proposer member id, proposal script, parameters, and votes, can be queried from the service by calling ``GET /gov/proposals/{proposal_id}``. For example, after accepting the proposal above:

.. code-block:: bash

    # The full proposal state, including votes, can still be retrieved by any member
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --cacert networkcert.pem --key member3_privk.pem --cert member3_cert.pem -H "content-type: application/json" -X GET
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
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Withdrawn"
    }

This means future votes will be rejected, and the proposal will never be accepted. However it remains visible as a proposal so members can easily audit historic proposals.
