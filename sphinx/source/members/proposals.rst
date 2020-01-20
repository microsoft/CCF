Proposing and Voting for a Proposal
===================================

This page explains how members can submit and vote for proposals before they get accepted.

Any member (proposer) can submit a new proposal. Other members can then vote on this proposal using its unique proposal id.

Once a :term:`quorum` of members (as defined by the :term:`constitution`) has accepted the proposal, the proposal gets executed and its effects recorded in the ledger.

For transparency and auditability, all governance operations (including votes) are recorded in plaintext in the ledger and members are required to sign their requests.

Submitting a new proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using the ``memberclient`` command-line utility (see :ref:`members/member_rpc_api:Member RPC API` for equivalent JSON-RPC API).

For example, ``member1`` may submit a proposal to add a new member (``member4``) to the consortium:

.. code-block:: bash

    $ memberclient --rpc-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem add_member --member-cert member4_cert.pem
    {"commit":100,"global_commit":99,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

In this case, a new proposal with id ``1`` has successfully been created and the proposer member has automatically accepted it. Other members can then accept or reject the proposal:

.. code-block:: bash

    // Proposal 1 is already created by member 1 (votes: 1/3)

    // Member 2 rejects the proposal (votes: 1/3)
    $ memberclient --rpc-address 127.83.203.69:55526 --cert member2_cert.pem --privk member2_privk.pem --ca networkcert.pem vote --reject --proposal-id 1
    {"commit":104,"global_commit":103,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    // Member 3 accepts the proposal (votes: 2/3)
    // As a majority of members have accepted the proposal, member4 is added to the consortium
    $ memberclient --rpc-address 127.83.203.69:55526 --cert member3_cert.pem --privk member3_privk.pem --ca networkcert.pem vote --accept --proposal-id 1
    {"commit":106,"global_commit":105,"id":0,"jsonrpc":"2.0","result":true,"term":2}

As soon as ``member3`` accepts the proposal, a majority (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active:

    .. code-block:: bash

        $ memberclient --rpc-address 127.83.203.69:55526 --cert member4_cert.pem --privk member4_privk.pem --ca networkcert.pem ack
        {"commit":108,"global_commit":107,"id":2,"jsonrpc":"2.0","result":true,"term":2}


Displaying proposals
--------------------

The details of pending proposals, including the proposer member id, proposal script, parameters and votes, can be displayed with the ``proposal_display`` sub command of the ``memberclient`` utility. For example:

.. code-block:: bash

    $ memberclient --rpc-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem proposal_display
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

Withdrawing a proposal
----------------------

At any stage during the voting process and before the proposal is completed, the proposing member may decide to withdraw a pending proposal:

.. code-block:: bash

    $ memberclient --rpc-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem withdraw --proposal-id 0
    {"commit":110,"global_commit":109,"id":0,"jsonrpc":"2.0","result":true,"term":4}

This means future votes will be ignored, and the proposal will never be accepted. However it will remain visible as a proposal so members can easily audit historic proposals.