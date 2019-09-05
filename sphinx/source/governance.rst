Governance
==========

A trusted set of members is in charge of governing a given CCF network. For transparency and auditability, all governance operations are recorded in plaintext in the ledger.

One member (proposer) can submit a new proposal. Once they have done this, other members can vote for the proposal using its unique proposal ID. Proposals are executed once a :term:`quorum` of members have accepted it.

The quorum is defined as a Lua script in the genesis transaction (see for example `the default quorum script`_). Common governance operations include adding a new user, member or a new version of the CCF code.

.. note:: A proposal can be a Lua script defined by the proposer member or a static function defined by CCF (e.g. ``new_member``).

.. _`the default quorum script`: https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov.lua

Submitting a new proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the quorum is defined as a strict majority of members, a member can submit a new proposal using the ``memberclient`` command-line utility (see :ref:`Member methods` for equivalent JSON-RPC API).

For example, ``member1`` may submit a proposal to add a new member (``member4``) to the consortium:

.. code-block:: bash

    $ memberclient --server-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem add_member --member-cert member4_cert.pem
    {"commit":100,"global_commit":99,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

In this case, a new proposal with id ``1`` has successfully been created and the proposer member has automatically accepted it. Other members can then accept or reject the proposal:

.. code-block:: bash

    // Proposal 1 is already created by member 1 (votes: 1/3)

    // Member 2 rejects the proposal (votes: 1/3)
    $ memberclient --server-address 127.83.203.69:55526 --cert member2_cert.pem --privk member2_privk.pem --ca networkcert.pem vote --reject --proposal-id 1
    {"commit":104,"global_commit":103,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    // Member 3 accepts the proposal (votes: 2/3)
    // As a quorum of members have accepted the proposal, member4 is added to the consortium
    $ memberclient --server-address 127.83.203.69:55526 --cert member3_cert.pem --privk member3_privk.pem --ca networkcert.pem vote --accept --proposal-id 1
    {"commit":106,"global_commit":105,"id":0,"jsonrpc":"2.0","result":true,"term":2}

As soon as ``member3`` accepts the proposal, a quorum (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active:

    .. code-block:: bash

        $ memberclient --server-address 127.83.203.69:55526 --cert member4_cert.pem --privk member4_privk.pem --ca networkcert.pem ack
        {"commit":108,"global_commit":107,"id":2,"jsonrpc":"2.0","result":true,"term":2}


Displaying proposals
--------------------

The details of pending proposals, including the proposer member ID, proposal script, parameters and votes, can be displayed with the ``proposal_display`` sub command of the ``memberclient`` utility. For example:

.. code-block:: bash

    $ memberclient --server-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem proposal_display
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

In this case, there is one pending proposal (``id`` is 1), proposed by the first member (``member1``, ``id`` is 0) and which will call the ``accept_node`` function with the new member's certificate as a parameter. Two votes have been cast: ``member1`` (proposer) has voted for the proposal, while ``member2`` (``id`` is 1) has voted against it.

Withdrawing proposals
---------------------

At any stage during the voting process and before the proposal is completed, the proposing member may decide to withdraw a pending proposal:

.. code-block:: bash

    $ memberclient --server-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem withdraw --proposal-id 0
    {"commit":110,"global_commit":109,"id":0,"jsonrpc":"2.0","result":true,"term":4}

This means future votes will be ignored, and the proposal will never be accepted. However it will remain visible as a proposal so members can easily audit historic proposals.

