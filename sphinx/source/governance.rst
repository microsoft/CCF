Governance
==========

A trusted set of members is in charge of governing a given CCF network. For transparency and auditability, all governance operations are recorded in plaintext in the ledger.

One member (proposer) may submit a new proposal after which other members can vote for the proposal using its unique proposal ID. Proposals are executed once a quorum of members have accepted a proposal.

The quorum is defined as a Lua script in the genesis transaction (see for example `the default quorum script`_). Common governance operations include adding a new user, member or a new version of the CCF code.

.. note:: A proposal can be a Lua script defined by the proposer member or a static function defined by CCF (e.g. ``new_member``).

.. _`the default quorum script`: https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov.lua

Submitting a new proposal
-------------------------

Assuming that 3 members (``member1``, ``member2`` and ``member3``) is already registered in the CCF network and that the quorum is defined as a strict majority of members, a member can submit a new proposal using the ``memberclient`` command-line utility (see :ref:`Member methods` for equivalent JSON-RPC API).

For example, ``member1`` may submit a proposal to add a new member (``member4``) to the consortium:

.. code-block:: bash

    $ memberclient add_member --cert=member1_cert.pem --privk=member1_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem --member_cert=member4_cert.pem
    {"commit":100,"global_commit":99,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

In this case, the proposal has successfully been created and given the proposal id ``1``. Other members, including ``member1``, can then accept or reject the proposal:

.. code-block:: bash

    // Member 1 accepts the proposal
    $ memberclient vote --accept --id=1 --cert=member1_cert.pem --privk=member1_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem --sign
    {"commit":102,"global_commit":101,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    // Member 2 rejects the proposal
    $ memberclient vote --reject --id=1 --cert=member2_cert.pem --privk=member2_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem --sign
    {"commit":104,"global_commit":103,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    // Member 3 accepts the proposal
    // A quorum of members have accepted the proposal, member4 is added to the consortium
    $ memberclient vote --accept --id=1 --cert=member3_cert.pem --privk=member3_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem --sign
    {"commit":106,"global_commit":105,"id":0,"jsonrpc":"2.0","result":true,"term":2}

As soon as ``member3`` accepts the proposal, a quorum (2 out of 3) of members has been reached and the proposal completes, successfully adding ``member4``.

.. note:: Once a new member has been accepted to the consortium, the new member must acknowledge that it is active:

    .. code-block:: bash

        $ ../build/memberclient ack --cert=member4_cert.pem --privk=member4_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem --sign
        {"commit":108,"global_commit":107,"id":2,"jsonrpc":"2.0","result":true,"term":2}


Displaying proposals
--------------------

Pending proposals, including the proposer member ID, proposal script, parameters and votes, can be displayed with the following command:

.. code-block:: bash

    $ memberclient display_proposal --cert=member1_cert.pem --privk=member1_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem
    ------ Proposal ------
    -- Proposal id: 1
    -- Proposer id: 0
    -- Script: {"text":"\n      tables, member_cert = ...\n      return Calls:call(\"new_member\", member_cert)\n    "}
    -- Parameter: [<member_certificate>]
    -- Votes: [[0,{"text":"\n      tables, changes = ...\n      return false"}]]
    ----------------------


Removing proposals
------------------

At any stage during the voting process and before the proposal is completed, the proposer member may decide to remove a pending proposal:

.. code-block:: bash

    $ memberclient removal --id=1 --cert=member1_cert.pem --privk=member1_privk.pem --host=10.1.0.4 --port=25000 --ca=networkcert.pem --sign
    {"commit":110,"global_commit":109,"id":0,"jsonrpc":"2.0","result":true,"term":4}