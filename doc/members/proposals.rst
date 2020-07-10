Proposing and Voting for a Proposal
===================================

This page explains how members can submit and vote for proposals.

Any member can submit a new proposal. All members can then vote on this proposal using its unique proposal id. Each member may alter their vote (by submitting a new vote) any number of times while the proposal is open. The member who originally submitted the proposal (the `proposer`) votes for the proposal by default, but has the option to include a negative or conditional vote like any other member. Additionally, the proposer has the ability to `withdraw` a proposal while it is open.

Each time a vote is submitted, all vote ballots for this proposal are re-executed on the current state to determine whether they are `for` or `against` the proposal. This vote tally is passed to the :term:`Constitution`, which determines whether the proposal is accepted or remains open. Once a proposal is accepted under the rules of the :term:`Constitution`, it is executed and its effects are recorded in the ledger.

For transparency and auditability, all governance operations (including votes) are recorded in plaintext in the ledger and members are required to sign their requests.

Submitting a New Proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using ``POST /gov/proposals`` and vote using ``POST /gov/proposals/{proposal_id}/votes``.

For example, ``member1`` may submit a proposal to add a new member (``member4``) to the consortium:

.. code-block:: bash

    $ cat new_member.json
    {
      "parameter": {
        "cert": "-----BEGIN CERTIFICATE-----\nMIIBrzCCATSgAwIBAgIUTu47sG/Ziz4hgoeMhKzs/alrEYcwCgYIKoZIzj0EAwMw\nDjEMMAoGA1UEAwwDYm9iMB4XDTIwMDcwOTE0NTc0OFoXDTIxMDcwOTE0NTc0OFow\nDjEMMAoGA1UEAwwDYm9iMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENhB3M5fWT5YQ\n+vBOl0T9xt29CvYBsJyLCGeflqLAFA4YDs7Bb3mMH46EiJg+BFT0HmIPtGW91qE5\nZEPMINQ2zuU0IU6uomPBi76pQ5vhm/2HDy3SLDwRytrSDNqTXZXfo1MwUTAdBgNV\nHQ4EFgQUBchpeGuTHjy4XuwdgQqC3pOqOdEwHwYDVR0jBBgwFoAUBchpeGuTHjy4\nXuwdgQqC3pOqOdEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEA\nmNPNpZvqn3piEepKGFJtqKtq+bZxUZuWZxxXILj4/qnC1fLatJaMQ/DHRtCxwcU/\nAjEAtZe3LAQ6NtVIrn4qFG3ruuEgFL9arCpFGEBLFkVdkL2nFIBTp1L4C1/aJBqk\nK9d9\n-----END CERTIFICATE-----\n",
        "keyshare": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAO63rFGghBlp4DUvFQ6437ZGBlB8LNHnzgNEjW5hRPHM=\n-----END PUBLIC KEY-----\n"
      },
      "script": {
        "text": "tables, args = ...; return Calls:call(\"new_member\", args)"
      }
    }

    $ ./scurl.sh https://<ccf-node-address>/gov/proposals --cacert network_cert --key member1_privk --cert member1_cert --data-binary @add_member.json -H "content-type: application/json"
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
    $ ./scurl.sh https://<ccf-node-address>/gov/proposals/4/votes --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_reject.json -H "content-type: application/json"
    {
      "proposal_id": 4,
      "proposer_id": 1,
      "state": "OPEN"
    }

    # Member 3 accepts the proposal (votes in favour: 2/3)
    $ ./scurl.sh https://<ccf-node-address>/gov/proposals/4/votes --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept.json -H "content-type: application/json"
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
    $ ./scurl.sh https://<ccf-node-address>/gov/proposals/4 --cacert networkcert.pem --key member3_privk.pem --cert member3_cert.pem -H "content-type: application/json" -X GET
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

    $ ./scurl.sh https://<ccf-node-address>/gov/proposals/<proposal-id>/withdraw --cacert networkcert.pem --key member1_privk.pem --cert member1_cert.pem -H "content-type: application/json"
    {
      "proposal_id": 4,
      "proposer_id": 1,
      "state": "WITHDRAWN"
    }

This means future votes will be rejected, and the proposal will never be accepted. However it remains visible as a proposal so members can easily audit historic proposals.