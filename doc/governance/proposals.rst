Proposing and Voting for a Proposal
===================================

.. note::
    See :doc:`/governance/js_gov` for pointers on converting from Lua to JS.

Summary
-------

Proposals are submitted as JSON documents, which if resolved successfully are applied atomically to the KV state.

Ballots are submitted as JavaScript modules exporting a single ``vote()`` function, executed transactionally, and are able to read from the current KV state but not write to it.
Each vote script is given the proposal as a JSON document, typically containing list of actions, and returns a Boolean value indicating whether it supports or rejects it.

Any member can submit a new proposal. All members can then vote, once at most, on this proposal using its unique proposal id.
The proposer has the ability to `withdraw` a proposal as long as it is open.

Each time a vote is submitted, all vote ballots for this proposal are re-executed on the current state to determine whether they are `for` or `against` the proposal.
This vote tally is passed to the ``resolve()`` call in the :term:`Constitution`, which determines whether the proposal is accepted or remains open.
Once a proposal is accepted under the rules of the :term:`Constitution`, it is executed via ``apply()`` and its effects are applied to the state and recorded in the ledger.

For transparency and auditability, all governance operations (including votes) are recorded in plaintext in the ledger and members are required to sign their requests.

.. mermaid::

    sequenceDiagram
        participant Member 0
        participant Member 1
        participant MemberFrontend
        participant Constitution

        Note over MemberFrontend, Constitution: CCF
        Member 0->>+MemberFrontend: Submit Proposal to /gov/proposals
        MemberFrontend->>+Constitution: call validate(Proposal)
        Constitution-->>-MemberFrontend: no exception
        MemberFrontend->>+Constitution: call resolve(Proposal, {})
        Constitution-->>-MemberFrontend: not enough votes, return Proposal is Open
        MemberFrontend-->>-Member 0: Proposal is Open

        Member 1->>+MemberFrontend: Submit Ballot containing vote() to /gov/proposals/ProposalID/ballots
        MemberFrontend->>MemberFrontend: evaluate vote(Proposal, KV State) to boolean Vote
        MemberFrontend->>+Constitution: call resolve(Proposal, {Member 1: Vote})
        Constitution-->>-MemberFrontend: enough positive votes, return Proposal is Accepted
        MemberFrontend->>+Constitution: call apply(Proposal) to perform side-effects
        Constitution-->>-MemberFrontend: no exception
        MemberFrontend-->>-Member 1: Proposal is Accepted, has successfully been applied


Creating a Proposal
-------------------

For custom proposals with multiple actions and precise conditional requirements you will need to write the proposal script by hand.
For simple proposals there is a helper script in the CCF Python package - ``proposal_generator.py``.
This can be used to create proposals for common operations like adding members and users, without writing any JSON.
It also produces sample vote scripts, which validate that the executed proposed actions exactly match what is expected.
These sample proposals and votes can be used as a syntax and API reference for producing more complex custom proposals.

Assuming the CCF Python package has been installed in the current Python environment, the proposal generator can be invoked directly as ``ccf.proposal_generator``. With no further argument it will print help text, including the list of possible actions as subcommands:

.. code-block:: bash

    usage: proposal_generator.py [-h] [-po PROPOSAL_OUTPUT_FILE] [-vo VOTE_OUTPUT_FILE] [-pp] [-i] [-v]
                                {add_node_code,remove_ca_cert_bundle,remove_js_app,remove_jwt_issuer,remove_member,remove_node,remove_node_code,remove_user,set_ca_cert_bundle,set_constitution,set_js_app,set_jwt_issuer,set_jwt_public_signing_keys,set_member,set_member_data,set_recovery_threshold,set_user,set_user_data,transition_node_to_trusted,transition_service_to_open,trigger_ledger_rekey,trigger_recovery_shares_refresh}

Additional detail is available from the ``--help`` option. You can also find the script in a checkout of CCF:

.. code-block:: bash

    $ python CCF/python/ccf/proposal_generator.py

Some of these subcommands require additional arguments, such as the node ID or user certificate to add to the service. Additional options allow the generated votes and proposals to be redirected to other files or pretty-printed:

.. code-block:: bash

    $ python -m ccf.proposal_generator transition_node_to_trusted 6d566123a899afaea977c5fc0f7a2a9fef33f2946fbc4abefbc3e10ee597343f
    SUCCESS | Writing proposal to ./trust_node_proposal.json
    SUCCESS | Wrote vote to ./trust_node_vote_for.json

    $ cat trust_node_proposal.json
    {"actions": [{"name": "transition_node_to_trusted", "args": {"node_id": "6d566123a899afaea977c5fc0f7a2a9fef33f2946fbc4abefbc3e10ee597343f"}}]}

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

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using ``POST /gov/proposals`` and vote using ``POST /gov/proposals/{proposal_id}/ballots``.

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

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member1_privk --cert member1_cert --data-binary @add_member.json -H "content-type: application/json"
    {
      "ballot_count": 0,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

Here a new proposal has successfully been created, and nobody has yet voted for it. The proposal is in state ``Open``, meaning it will can receive additional votes. Members can then vote to accept or reject the proposal:

.. code-block:: bash

    $ cat vote_reject.json
    {
      "ballot": "export function vote (proposal, proposerId) { return false }"
    }

    $ cat vote_accept.json
    {
      "ballot": "export function vote (proposal, proposerId) { return true }"
    }


    # Member 1 approves the proposal (votes in favour: 1/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert network_cert --key member1_privk --cert member1_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }


    # Member 2 rejects the proposal (votes in favour: 1/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_reject.json -H "content-type: application/json"
    {
      "ballot_count": 2,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

    # Member 3 accepts the proposal (votes in favour: 2/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept.json -H "content-type: application/json"
    {
      "ballot_count": 3,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Accepted"
    }

    # As a majority of members have accepted the proposal, member 4 is added to the consortium

As soon as ``member3`` accepts the proposal, a majority (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``. The response shows this, as the proposal's state is now ``Accepted``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active by sending a ``/gov/ack`` request. See :ref:`governance/adding_member:Activating a New Member`.

Displaying Proposals
--------------------

The details of pending proposals, can be queried from the service by calling ``GET /gov/proposals/{proposal_id}``. For example, after accepting the proposal above:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --cacert networkcert.pem --key member3_privk.pem --cert member3_cert.pem -H "content-type: application/json" -X GET
    {
      "ballots": {
        "0d8866bf4623a685963f3c087cd6fdcdf48fc483d774f7fc28bf428e31755aaa": "export function vote (proposal, proposerId) { return true }",
        "466cc43f0cd17df4b49ded4b833f7bbba43b15ebee5be896d91e823fcce96a69": "export function vote (proposal, proposerId) { return true }",
        "fe1b9b511fb3cf3ca3a1289b0d44db83a80dee8a54492f29467c52ebef9dbe40": "export function vote (proposal, proposerId) { return false }"
      },
      "final_votes": {
        "0d8866bf4623a685963f3c087cd6fdcdf48fc483d774f7fc28bf428e31755aaa": true,
        "466cc43f0cd17df4b49ded4b833f7bbba43b15ebee5be896d91e823fcce96a69": true,
        "fe1b9b511fb3cf3ca3a1289b0d44db83a80dee8a54492f29467c52ebef9dbe40": false
      },
      "proposer_id": "0d8866bf4623a685963f3c087cd6fdcdf48fc483d774f7fc28bf428e31755aaa",
      "state": "Accepted"
    }

Withdrawing a Proposal
----------------------

At any stage during the voting process, before the proposal is accepted, the proposing member may decide to withdraw a pending proposal:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/withdraw --cacert networkcert.pem --key member1_privk.pem --cert member1_cert.pem -H "content-type: application/json"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Withdrawn"
    }

This means future votes will be rejected, and the proposal will never be accepted. However it remains visible as a proposal so members can easily audit historic proposals.
