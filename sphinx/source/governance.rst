Governance
==========

A trusted set of members is in charge of governing a given CCF network. For transparency and auditability, all governance operations are recorded in plaintext in the ledger and members are required to sign their requests.

Any member (proposer) can submit a new proposal. Other members can then vote on this proposal using its unique proposal ID. Votes for the proposal are evaluated by the constitution's `pass` function.
If the `pass` function returns true, the vote is passed, and its consequences are applied to the KV in a transaction.

This `simple constitution`_ implements a "one-member, one-vote" constitution, with a majority rule. Votes on so-called sensitive tables, such as the one containing the constitution itself, require unanimity.

.. note:: A proposal can be a Lua script defined by the proposer member or a static function defined by CCF (e.g. ``new_member``).

Operations
----------

- :ref:`Adding users`
- Adding members
- :ref:`Opening a network`
- :ref:`Updating code`
- Accepting a new node to the network
- Accept :ref:`Catastrophic Recovery`

Submitting a new proposal
`````````````````````````

Assuming that 3 members (``member1``, ``member2`` and ``member3``) are already registered in the CCF network and that the sample constitution is used, a member can submit a new proposal using the ``memberclient`` command-line utility (see :ref:`Member methods` for equivalent JSON-RPC API).

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
````````````````````

The details of pending proposals, including the proposer member ID, proposal script, parameters and votes, can be displayed with the ``proposal_display`` sub command of the ``memberclient`` utility. For example:

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
``````````````````````

At any stage during the voting process and before the proposal is completed, the proposing member may decide to withdraw a pending proposal:

.. code-block:: bash

    $ memberclient --rpc-address 127.83.203.69:55526 --cert member1_cert.pem --privk member1_privk.pem --ca networkcert.pem withdraw --proposal-id 0
    {"commit":110,"global_commit":109,"id":0,"jsonrpc":"2.0","result":true,"term":4}

This means future votes will be ignored, and the proposal will never be accepted. However it will remain visible as a proposal so members can easily audit historic proposals.

Updating code
`````````````

For new nodes to be able to join the network, the version of the code they run (as specified by the ``--enclave-file``) should be first trusted by the consortium of members.

If the version of the code being executed needs to be updated (for example, to support additional endpoints), members can create a ``new_code`` proposal, specifying the new code version (e.g. ``3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9``):

.. code-block:: bash

    memberclient --cert member_cert --privk member_privk --rpc-address node_ip:node_port --ca network_cert add_code --new-code-id code_version

Once the proposal has been accepted, nodes running the new code are authorised join the network. Nodes running older versions of the code can then be retired and stopped.

.. note:: It is important to keep the code compatible with the previous version, since there will be a point in time in which the new code is running on at least one node, while the other version is running on a different node.

.. note:: The safest way to restart or replace nodes is by stopping a single node running the old version and starting a node running the new version as a sequence of operations, in order to avoid a situation in which most nodes have been stopped, and new nodes will not be able to join since it would be impossible to reach a majority of nodes agreeing to accept new nodes (this restriction is imposed by the consensus algorithm).


Models
------

The operators of a CCF network do not necessarily overlap with the members of that network. Although the scriptability of the governance model effectively allows a large number of possible arrangements, the following two schemes seem most likely:

Non-member operators
````````````````````

It is possible for a set of operators to host a CCF network without being members. These operators could:

- Start the network
- Hand it over to the members for them to Open (see :ref:`Opening a network`)

In case of catastrophic failure, operators could also:

- Start a network in recovery mode from the ledger
- Hand it over to the members for them to Open (see :ref:`Catastrophic Recovery`)

Finally, operators could:
-	Propose new nodes (TR, Section IV D)
-	Notify the members, who would have to review and vote on the proposal

Operators would not be able to add or remove members or users to the service. They would not be able to update the code of the service (and therefore apply security patches). Because they could propose new nodes, but would require member votes before nodes are allows to join, the operators' ability to mitigate node failures may be limited and delayed.

This model keeps operators out of the trust boundary for the service.

Operating members
`````````````````

If network operators are made members, they could have the ability to:

-	Update code (in particular, apply security patches)
-	Add and remove nodes to and from the network

Essentially, operators gain the ability to fix security issues and mitigate service degradation for the network. In this situation however, the operator is inside the trust boundary.

The constitution can limit or remove the operating members' ability to:

-	Add and remove members and users
-	Complete a recovery

.. note:: These limits are weakened by the operators' ability to update the code. A code update could contain changes that allow the operator to bypass constitution restrictions. Work is in progress to propose a service that would effectively mitigate this problem. In the absence of code updates however, other members of the service could trust that the operating members have not added or removed members and users, and have not executed a recovery.

This `operating member constitution`_ shows how some members can be made operators. 

.. _`simple constitution`_: https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov.lua

.. _`operating member constitution`_: https://github.com/microsoft/CCF/blob/master/src/runtime_config/operator_gov.lua