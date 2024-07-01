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

A proposal's body contains a JSON object with a list of desired actions.
The actions are identified by name, matching a function from the constitution which should be called to verify and apply this action.
Each action may have associated arguments.
The schema of these arguments is determined by the constitution which handles them, so they should be constructed with reference to a target constitution.
Some examples of proposals which could be sent to the default sample constitution provided with CCF:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_user",
          "args": {
            "cert": "-----BEGIN CERTIFICATE-----\nMIIBszCCATigAwIBAgIUeYsXeSyujwWWSySPlaVxP0pfO/EwCgYIKoZIzj0EAwMw\nEDEOMAwGA1UEAwwFdXNlcjMwHhcNMjIwMTEyMTAxOTM0WhcNMjMwMTEyMTAxOTM0\nWjAQMQ4wDAYDVQQDDAV1c2VyMzB2MBAGByqGSM49AgEGBSuBBAAiA2IABLWb5TWU\nX9+ldfOZAyEZkbgb7n5CDZcfWXkyL6QXQI7OJb0uF9P6AOuErd/q5Vv2Mqg8LnJs\nmZafY9qZ1Z9XbfOkh5DI08PipIgDBIQ7BYIgstWege/rppcFKuqgjGm1waNTMFEw\nHQYDVR0OBBYEFOhjbOPTvy4iZ7+PFXvYY8Sm1lxcMB8GA1UdIwQYMBaAFOhjbOPT\nvy4iZ7+PFXvYY8Sm1lxcMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaQAw\nZgIxAJHzWMG/CeEg+lfI7gwCv4GEPqc1mZj5PT9uIvFso5NQe36L1UFhMCJDx4g0\nx7rQdwIxAJ5145d33LLc+Row4lOEAiHJpzivurLl4y5Kx6SkY3JMQbmGPJaslPWm\nxfWXoAcGhQ==\n-----END CERTIFICATE-----\n",
          }
        }
      ]
    }

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_node_certificate_validity",
          "args": {
            "node_id": "ba9faac9683f7854c2cf0a97f57e63c260bf8d06f8183772c5655093c0af6e19",
            "valid_from": "220112101937Z",
            "validity_period_days": 366
          }
        }
      ]
    }

.. code-block:: json

    {
      "actions": [
        {
          "name": "transition_node_to_trusted",
          "args": {
            "node_id": "ba9faac9683f7854c2cf0a97f57e63c260bf8d06f8183772c5655093c0af6e19",
            "valid_from": "220101120000Z"
          }
        },
        {
          "name": "transition_node_to_trusted",
          "args": {
            "node_id": "5d5b09f6dcb2d53a5fffc60c4ac0d55fabdf556069d6631545f42aa6e3500f2e",
            "valid_from": "220101120000Z"
          }
        },
        {
          "name": "transition_service_to_open",
          "args": {
              "next_service_identity": "-----BEGIN CERTIFICATE-----\nMIIBuDCCAT2gAwIBAgIQLvCv036OU/z8myGLWx0vtTAKBggqhkjOPQQDAzAWMRQw\nEgYDVQQDDAtDQ0YgTmV0d29yazAeFw0yMjAzMTUxNjM2MzVaFw0yMjAzMTYxNjM2\nMzRaMBYxFDASBgNVBAMMC0NDRiBOZXR3b3JrMHYwEAYHKoZIzj0CAQYFK4EEACID\nYgAEKP9wIDb6ROuLKBYkvqB3zDo3xIvF8KVaEGUaB5/k8RBCKMZuYN77+ZkchJ1W\nIx/k+/qHfilcmYGPtU0HfClhhmRVVz7HmGH/BNC2WD7xv7/4XKAKRyBaPrgKV1kM\nVUYmo1AwTjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBSrcP9JAIud2nXS7JeIqmmy\ncJMT4TAfBgNVHSMEGDAWgBSrcP9JAIud2nXS7JeIqmmycJMT4TAKBggqhkjOPQQD\nAwNpADBmAjEA3LvcHZtTrJ1r1FvodfU1ExO5mjLZbNs3SQA2ztoR9/ZSq9kzxInn\nHD25MYYpZx8WAjEAvxuxS33yJ3e8f08hZbMb687mnPOiPl3bw5/GDCMvsTRAmIn9\nX+bORxJ2HnYGd3Jj\n-----END CERTIFICATE-----\n"
          }
        }
      ]
    }

Most HTTP client libraries and tools should have functionality for constructing and providing these JSON objects, and constitutions should be written to provide clear validation errors if a proposal is malformed.

A ballot's body contains a JS function which evaluates a given proposal, embedded inside a JSON object.
These may try to confirm the precise content equality of the proposal they are considering, or put some constraints on its parameters.
They could also be simple positive/negative votes, in a model where members fetch and validate a proposal offline before submitting their votes.
Some example ballots which could apply to the proposals above:

.. code-block:: json

    {
      "ballot": "export function vote (rawProposal, proposerId)\n
      {\n
        // Accepts any proposal\n
        return true;\n
      }"
    }

.. code-block:: json

    {
      "ballot": "export function vote (rawProposal, proposerId)\n
      {\n
        // Refuses every proposal\n
        return false;\n
      }"
    }

.. code-block:: json

    {
      "ballot": "export function vote (rawProposal, proposerId)\n
      {\n
        // Accepts 'set_node_certificate_validity' proposals with a max validity period of 1 year\n
        let proposal = JSON.parse(rawProposal);\n
        let action = proposal[\"actions\"][0];\n
        if (action[\"name\"] === \"set_node_certificate_validity\") {\n
          let action_args = action[\"args\"];\n
          if (action_args[\"validity_period_days\"] <= 365) {\n
            return true;\n
          }\n
        }\n
        return false;\n
      }"
    }

The CCF repository includes a sample Jinja template which will automatically build a ballot, doing a structural equality check against a target proposal. For example if this was run for the ``set_node_certificate_validity`` proposal above:

.. code-block:: bash

    # Relies on jinja-cli:
    #   pip install jinja-cli
    $ jinja ballot_script.js.jinja -d proposal.json

    export function vote (rawProposal, proposerId) {
      let proposal = JSON.parse(rawProposal);
      if (!("actions" in proposal))
      {
        return false;
      }

      let actions = proposal["actions"];
      if (actions.length !== 1 )
      {
        return false;
      }

      // Check that the "set_node_certificate_validity" action is exactly what was expected
      {
        let action = actions[0];
        if (!("name" in action))
        {
          return false;
        }

        if (action.name !== "set_node_certificate_validity")
        {
          return false;
        }


        if (!("args" in action))
        {
          return false;
        }

        let args = action.args;

        // Check each argument
        {
          if (!("node_id" in args))
          {
            return false;
          }

          // Compare stringified JSON representation, to cover object equality
          const expected = JSON.stringify("ba9faac9683f7854c2cf0a97f57e63c260bf8d06f8183772c5655093c0af6e19");
          if (JSON.stringify(args["node_id"]) !== expected)
          {
            return false;
          }
        } 
        // Check each argument
        {
          if (!("valid_from" in args))
          {
            return false;
          }

          // Compare stringified JSON representation, to cover object equality
          const expected = JSON.stringify("220112101937Z");
          if (JSON.stringify(args["valid_from"]) !== expected)
          {
            return false;
          }
        } 
        // Check each argument
        {
          if (!("validity_period_days" in args))
          {
            return false;
          }

          // Compare stringified JSON representation, to cover object equality
          const expected = JSON.stringify(366);
          if (JSON.stringify(args["validity_period_days"]) !== expected)
          {
            return false;
          }
        } 
      }

      return true;
    }

The ``ballot.json.jinja`` template will additionally embed this script in a JSON object.

These proposals and votes should be sent as the body of HTTP requests as described below.

Submitting a New Proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using :http:POST:`/gov/proposals` and vote using :http:POST:`/gov/proposals/{proposal_id}/ballots`.

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

.. code-block:: bash

    $ ccf_cose_sign1 --ccf-gov-msg-type proposal --ccf-gov-msg-created_at `date -Is` --signing-key member1_privk.pem --signing-cert member1_cert.pem --content add_member.json | \
      curl https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
      "ballot_count": 0,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem --data-binary @add_member.json -H "content-type: application/json"
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

.. code-block:: bash

    # Member 1 approves the proposal (votes in favour: 1/3)
    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-created_at `date -Is` --ccf-gov-msg-proposal_id d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --signing-key member1_privk.pem --signing-cert member1_cert.pem --content vote_accept.json | \
      curl https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

    # Member 2 approves the proposal (votes in favour: 1/3)
    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-created_at `date -Is` --ccf-gov-msg-proposal_id d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --signing-key member2_privk.pem --signing-cert member2_cert.pem --content vote_reject.json | \
      curl https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
      "ballot_count": 2,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

    # Member 3 approves the proposal (votes in favour: 2/3)
    $ ccf_cose_sign1 --ccf-gov-msg-type ballot --ccf-gov-msg-created_at `date -Is` --ccf-gov-msg-proposal_id d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --signing-key member3_privk.pem --signing-cert member3_cert.pem --content vote_accept.json | \
      curl https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
      "ballot_count": 3,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Accepted"
    }

    # As a majority of members have accepted the proposal, member 4 is added to the consortium

Or alternatively, with the old signature method:

.. code-block:: bash

    # Member 1 approves the proposal (votes in favour: 1/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem --data-binary @vote_accept.json -H "content-type: application/json"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }


    # Member 2 rejects the proposal (votes in favour: 1/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert service_cert.pem --signing-key member2_privk.pem --signing-cert member2_cert.pem --data-binary @vote_reject.json -H "content-type: application/json"
    {
      "ballot_count": 2,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Open"
    }

    # Member 3 accepts the proposal (votes in favour: 2/3)
    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/ballots --cacert service_cert.pem --signing-key member3_privk.pem --signing-cert member3_cert.pem --data-binary @vote_accept.json -H "content-type: application/json"
    {
      "ballot_count": 3,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Accepted"
    }

    # As a majority of members have accepted the proposal, member 4 is added to the consortium

As soon as ``member3`` accepts the proposal, a majority (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``. The response shows this, as the proposal's state is now ``Accepted``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active by sending a :http:POST:`/gov/ack` request. See :ref:`governance/adding_member:Activating a New Member`.

Displaying Proposals
--------------------

The details of pending proposals, can be queried from the service by calling :http:GET:`/gov/proposals/{proposal_id}`. For example, after accepting the proposal above:

.. code-block:: bash

    $ curl https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --cacert service_cert.pem -X GET
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

    $ ccf_cose_sign1 --ccf-gov-msg-type withdrawal --ccf-gov-msg-created_at `date -Is` --ccf-gov-msg-proposal_id d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd --signing-key member1_privk.pem --signing-cert member1_cert.pem | \
      curl https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/withdraw --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Withdrawn"
    }

Or alternatively, with the old signature method:

.. code-block:: bash

    $ scurl.sh https://<ccf-node-address>/gov/proposals/d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd/withdraw --cacert service_cert.pem --signing-key member1_privk.pem --signing-cert member1_cert.pem -H "content-type: application/json"
    {
      "ballot_count": 1,
      "proposal_id": "d4ec2de82267f97d3d1b464020af0bd3241f1bedf769f0fee73cd00f08e9c7fd",
      "proposer_id": "52af2620fa1b005a93d55d7d819a249ee2cb79f5262f54e8db794c5281a0ce73",
      "state": "Withdrawn"
    }

This means future votes will be rejected, and the proposal will never be accepted. However it remains visible as a proposal so members can easily audit historic proposals.

Binding a Proposal
------------------

A member submitting a proposal may wish to bind it to a particular service instance. This is to prevent potential unwanted re-use of that proposal on other services, in which that member may be also be part of the consortium.

The `assert_service_identity` action, provided as a sample, illustrates how this can be done. It can be included in the proposal, with the service identity as a parameter:

.. code-block:: bash

    {
      "actions": [
        {
          "name": "assert_service_identity",
          "args": {
            "service_identity": "-----BEGIN CERTIFICATE-----\nMIIBsjCCATigAwIBAgIUTW9Zkzdbml7R3pZlp5qMgUUjPoYwCgYIKoZIzj0EAwMw\nEDEOMAwGA1UEAwwFdXNlcjAwHhcNMjIwOTEyMTM1ODIzWhcNMjMwOTEyMTM1ODIz\nWjAQMQ4wDAYDVQQDDAV1c2VyMDB2MBAGByqGSM49AgEGBSuBBAAiA2IABLeWHRm2\nEkAKOrf3r0xt6jjThD1A1zeu2ONtQk87O7EpAsPRKoPyemngpTZaMkRd8TfZSsYP\nLS9OBAHtNMZ3hR8dZL0dRZcCG34zcyImAkgOk903PXKE94xzTBnfhaHG6qNTMFEw\nHQYDVR0OBBYEFArH2udKBPnWXTbJ6UTt3jh4BXziMB8GA1UdIwQYMBaAFArH2udK\nBPnWXTbJ6UTt3jh4BXziMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaAAw\nZQIxAJ7WeiDh16x4dL5tHl5SlNpBkPQW1HArvSyeG5DYDWZSFVWTHKnrkVzDvC8B\nbXtzhwIwdFM365Ag8FvDyJXPrIONfURm7fkXU2evlh6QKna3zRxcZKnLGsha01Vh\nP9BX000h\n-----END CERTIFICATE-----\n"
          }
        }
      ]
    }

A constitution wishing to enforce that all proposals must be specific to a service could enforce the presence of this action in its ``validate()`` implementation.