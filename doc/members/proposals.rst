Proposing and Voting for a Proposal
===================================

This page explains how members can submit and vote for proposals before they get accepted.

Any member (proposer) can submit a new proposal. Other members can then vote on this proposal using its unique proposal id.

Once a proposal is accepted under the rules of the :term:`Constitution`, it is executed and its effects are recorded in the ledger.

For transparency and auditability, all governance operations (including votes) are recorded in plaintext in the ledger and members are required to sign their requests.

Submitting a New Proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using ``members/propose`` and vote using ``members/vote``.

For example, ``member1`` may submit a proposal to add a new member (``member4``) to the consortium:

.. code-block:: bash

    $ cat add_member.json
    {
        "parameter": {"cert": [<cert of member4>], "keyshare": [<public keyshare of member4>]},
        "script": {
            "text": "tables, member_info = ...; return Calls:call(\"new_member\", member_info)"
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/members/propose --cacert network_cert --key member1_privk --cert member1_cert --data-binary @add_member.json -H "content-type: application/json"
    {
      "completed": false,
      "id": 1
    }

In this case, a new proposal with id ``1`` has successfully been created and the proposer member has voted to accept it (they may instead pass a voting ballot with their proposal if they wish to vote conditionally, or withhold their vote until later). Other members can then vote to accept or reject the proposal:

.. code-block:: bash

    // Proposal 1 is already created by member 1 (votes: 1/3)

    $ cat vote_reject.json
    {
        "ballot": {
            "text": "return false"
        },
        "id": 0
    }

    $ cat vote_accept.json
    {
        "ballot": {
            "text": "return true"
        },
        "id": 0
    }

    // Member 2 rejects the proposal (votes: 1/3)
    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_reject.json -H "content-type: application/json"
    false

    // Member 3 accepts the proposal (votes: 2/3)
    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member3_privk --cert member3_cert --data-binary @vote_accept.json -H "content-type: application/json"
    true

    // As a majority of members have accepted the proposal, member4 is added to the consortium

As soon as ``member3`` accepts the proposal, a majority (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active by sending a ``members/ack`` request, signing their current nonce. See :ref:`members/adding_member:Activating a New Member`.

Displaying Proposals
--------------------

The details of pending proposals, including the proposer member id, proposal script, parameters, and votes, can be queried from the service by calling ``members/query`` and reading the ``ccf.proposals`` table. For example:

.. code-block:: bash

    $ cat display_proposals.json
    {
      "text": "tables = ...; local proposals = {}; tables[\"ccf.proposals\"]:foreach( function(k, v) proposals[tostring(k)] = v; end ) return proposals;"
    }

    $ ./scurl.sh https://<ccf-node-address>/members/query --cacert networkcert.pem --key member0_privk.pem --cert member0_cert.pem --data-binary @display_proposals.json -H "content-type: application/json"
    {
      "1": {
        "parameter": [...],
        "proposer": 0,
        "script": {
          "text": "tables, member_cert = ...\n return Calls:call(\"new_member\", member_cert)"
        },
        "votes": [
          [
            0,
            {
              "text": "return true"
            }
          ],
          [
            1,
            {
              "text": "return false"
            }
          ]
        ]
      }
    }

In this case, there is one pending proposal (``id`` is 1), proposed by the first member (``member1``, ``id`` is 0) and which will call the ``new_member`` function with the new member's certificate as a parameter. Two votes have been cast: ``member1`` (proposer) has voted for the proposal, while ``member2`` (``id`` is 1) has voted against it.

Withdrawing a Proposal
----------------------

At any stage during the voting process and before the proposal is completed, the proposing member may decide to withdraw a pending proposal:

.. code-block:: bash

    $ cat withdraw_0.json
    {
      "id": 0
    }

    $ ./scurl.sh https://<ccf-node-address>/members/withdraw --cacert networkcert.pem --key member0_privk.pem --cert member0_cert.pem --data-binary @withdraw_0.json -H "content-type: application/json"
    true

This means future votes will be ignored, and the proposal will never be accepted. However it will remain visible as a proposal so members can easily audit historic proposals.