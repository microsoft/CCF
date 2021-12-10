Proposing and Voting for a Proposal
===================================

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

Proposals are JSON objects specifying a list of actions and associated arguments. The name of the action should match one of the actions available in your service (in ``actions.js``), and the expected types of the arguments are dictated by the validate and apply functions which handle that action.
These proposal objects can be constructed by any tool or language which can produce JSON. The CCF pip package contains a sample of a tool to automate proposal creation, written in bash and wrapping the CLI tool ``jq``, named ``build_proposal.sh``:

.. code-block:: bash

    $ build_proposal.sh --help

    Usage:
      build_proposal.sh [--help | --action ACTION_NAME [[FLAGS] ARG_NAME ARG_VALUE...]...]

    This tool is a wrapper around jq, to simplify creation of CCF governance
    proposals.
    Specify a list of actions and associated args. A single flag per argument can be
    used to indicate how the value should be parsed:
      -s String (default)
      -j JSON (including raw numbers)
      -b Boolean (including case-insensitive parsing)
    Additionally, any @-prefixed string is treated as a file path, and will be
    replaced with the contents of the file.

    For example:
      build_proposal.sh
        --action set_greeting message HelloWorld -j max_repetitions 42
        --action no_arg_action
        --action upload_file contents @file.txt

    Will produce:
    {
      "actions": [
        {
          "name": "set_greeting",
          "args": {
            "message": "HelloWorld",
            "max_repetitions": 42
          }
        },
        {
          "name": "no_arg_action"
        },
        {
          "name": "upload_file",
          "args": {
            "contents": "This is a file.\nContaining multiple lines."
          }
        }
      ]
    }

Ballots are JSON objects containing a JS script exporting a single ``vote`` function, which parse a proposal and return a boolean to indicate the submitter's conditional assent (true to vote in favour, false to vote against). These votes may be hand-written to logically validate complex proposals, but for simple proposals it is often sufficient to do an equality check. Given a proposal object, we can generate a ballot which implements this equality check. Within the CCF pip package there are sample Jinja templates to generate these objects and scripts, and a Python script that demonstrates rendering these templates from a proposal, named ``ballot_builder``:

.. code-block:: bash

    $ python -m ccf.ballot_builder --help

    usage: ballot_builder.py [-h] proposal

    positional arguments:
      proposal       Path to proposal JSON file

    optional arguments:
      -h, --help     show this help message and exit

These tools can also be found in a checkout of CCF, under the ``python/`` directory.

.. note:: Both of these tools print their results (the generated proposal or ballot) directly to stdout on success, so you will likely want to redirect the output to a file to be used later.

For example, to add a new user to the service (using the default ``actions.js``), we call the ``set_user`` proposal, which expects the user's certificate in an argument named ``cert``. The ``build_proposal.sh`` script can read the cert directly from a file and insert that into the generated proposal by prefixing the argument value with ``@``:

.. code-block:: bash

    $ build_proposal.sh --action set_user cert @pedro_cert.pem > set_user_pedro.json

    $ cat set_user_pedro.json 
    {
      "actions": [
        {
          "name": "set_user",
          "args": {
            "cert": "-----BEGIN CERTIFICATE-----\nMIIBsjCCATigAwIBAgIUPutF1tdOKYecWwiX6FHw99I7QWIwCgYIKoZIzj0EAwMw\nEDEOMAwGA1UEAwwFcGVkcm8wHhcNMjExMjA5MTQ0OTE2WhcNMjIxMjA5MTQ0OTE2\nWjAQMQ4wDAYDVQQDDAVwZWRybzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJi0tNaU\nWmstK3Sx0pIEuQQT8gNlWLV1El3WnXYRQSaRKAVH5MRZIMPxxQbU17WA8IYOhzel\nzgp0A91JN7jB2bqYzhV/liWIbPpGw5lIFX4eeBF7tOyZeaGc1j35sKUveKNTMFEw\nHQYDVR0OBBYEFEVkwYquNo8Nk4yVDyRz74EG+lTNMB8GA1UdIwQYMBaAFEVkwYqu\nNo8Nk4yVDyRz74EG+lTNMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaAAw\nZQIwXweMn2htClgJlvukyHC8qIFpelPXmtJRuJ77VyDfqqQSDcVLl4sNGAHjqprv\nBYPmAjEA1XvpLLmPvIMfiwXeapgFnUzajFsuT3qzgWVgfED6E9B3kvQUhx6ZRG1l\np+BCBQGl\n-----END CERTIFICATE-----"
          }
        }
      ]
    }

We can auto-generate a ballot for this proposal:

.. code-block:: bash

    $ ballot_builder.py set_user_pedro.json > vote_for_pedro.json

    $ cat vote_for_pedro.json 
    {
      "ballot": "export function vote (rawProposal, proposerId) {\n  let proposal = JSON.parse(rawProposal);\n  if (!(\"actions\" in proposal))\n  {\n    return false;\n  }\n\n  let actions = proposal[\"actions\"];\n  if (actions.length !== 1 )\n  {\n    return false;\n  }\n\n  // Check that the \"set_user\" action is exactly what was expected\n  {\n    let action = actions[0];\n    if (!(\"name\" in action))\n    {\n      return false;\n    }\n\n    if (action.name !== \"set_user\")\n    {\n      return false;\n    }\n\n\n    if (!(\"args\" in action))\n    {\n      return false;\n    }\n\n    let args = action.args;\n\n    // Check each argument\n    {\n      if (!(\"cert\" in args))\n      {\n        return false;\n      }\n\n      // Compare stringified JSON representation, to cover object equality\n      const expected = JSON.stringify(\"-----BEGIN CERTIFICATE-----\\nMIIBsjCCATigAwIBAgIUPutF1tdOKYecWwiX6FHw99I7QWIwCgYIKoZIzj0EAwMw\\nEDEOMAwGA1UEAwwFcGVkcm8wHhcNMjExMjA5MTQ0OTE2WhcNMjIxMjA5MTQ0OTE2\\nWjAQMQ4wDAYDVQQDDAVwZWRybzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJi0tNaU\\nWmstK3Sx0pIEuQQT8gNlWLV1El3WnXYRQSaRKAVH5MRZIMPxxQbU17WA8IYOhzel\\nzgp0A91JN7jB2bqYzhV/liWIbPpGw5lIFX4eeBF7tOyZeaGc1j35sKUveKNTMFEw\\nHQYDVR0OBBYEFEVkwYquNo8Nk4yVDyRz74EG+lTNMB8GA1UdIwQYMBaAFEVkwYqu\\nNo8Nk4yVDyRz74EG+lTNMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaAAw\\nZQIwXweMn2htClgJlvukyHC8qIFpelPXmtJRuJ77VyDfqqQSDcVLl4sNGAHjqprv\\nBYPmAjEA1XvpLLmPvIMfiwXeapgFnUzajFsuT3qzgWVgfED6E9B3kvQUhx6ZRG1l\\np+BCBQGl\\n-----END CERTIFICATE-----\");\n      if (JSON.stringify(args[\"cert\"]) !== expected)\n      {\n        return false;\n      }\n    } \n  }\n\n  return true;\n}"
    }

To encode non-string arguments, we must pass a flag to the generator telling it the argument is raw JSON. Compare:

.. code-block:: bash

    $ build_proposal.sh --action set_recovery_threshold threshold 42
    {
      "actions": [
        {
          "name": "set_recovery_threshold",
          "args": {
            "threshold": "42"
          }
        }
      ]
    }

    $ build_proposal.sh --action set_recovery_threshold threshold -j 42
    {
      "actions": [
        {
          "name": "set_recovery_threshold",
          "args": {
            "threshold": 42
          }
        }
      ]
    }

These proposals and ballots should be sent as the body of HTTP requests as described below.

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

.. note:: Requests which affect governance must be signed, so this request is submitted by ``scurl.sh`` rather than ``curl``. If you do not sign a request which the service expects to be signed, it will return a ``401 Unauthorized`` response.

Here a new proposal has successfully been created, and nobody has yet voted for it. The proposal is in state ``Open``, meaning it can receive additional votes. Members can then vote to accept or reject the proposal:

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
