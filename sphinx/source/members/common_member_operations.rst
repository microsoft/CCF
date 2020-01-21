Common Governance Operations
============================

Trusting a New Node
-------------------

As opposed to an opening network in which nodes are trusted automatically, new nodes added to an open network must be trusted by a quorum of members before becoming part of the network.

When an operator starts a new node with the ``join`` option (see :ref:`operators/start_network:Adding a New Node to the Network`), the joining node is assigned a unique node id and is recorded in state `PENDING`. Then, members can vote to accept the new node, using the unique assigned node id:

.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert trust_node --node-id new_node_id
    {"commit":13,"global_commit":12,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":2},"term":2}

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 2 --accept
    {"commit":15,"global_commit":14,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 2 --accept
    {"commit":17,"global_commit":16,"id":0,"jsonrpc":"2.0","result":true,"term":2}

Once the proposal successfully completes, the new node automatically becomes part of the network.

.. note:: Once trusted, it may take some time for the new node to update its ledger and replay the transactions run on the network before it joined.

Updating Code Version
---------------------

For new nodes to be able to join the network, the version of the code they run (as specified by the ``--enclave-file``) should be first trusted by the consortium of members.

If the version of the code being executed needs to be updated (for example, to support additional endpoints), members can create a ``new_code`` proposal, specifying the new code version (e.g. ``3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9``):

.. code-block:: bash

    $ memberclient --cert member_cert --privk member_privk --rpc-address node_ip:node_port --ca network_cert add_code --new-code-id code_version

.. note:: For a given :term:`Open Enclave` enclave library, the version of the code (``mrenclave``) can be found by running the ``oesign`` utility:

    .. code-block:: bash

        $ /opt/openenclave/bin/oesign dump -e enclave_library
        === Entry point:
        name=_start
        address=000000000097fa38

        === SGX Enclave Properties:
        product_id=1
        security_version=1
        debug=1
        xfrm=0
        num_heap_pages=50000
        num_stack_pages=1024
        num_tcs=8
        mrenclave=3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9

Once the proposal has been accepted, nodes running the new code are authorised to join the network. Nodes running older versions of the code can then be retired and stopped.

.. note:: It is important to keep the code compatible with the previous version, since there will be a point in time in which the new code is running on at least one node, while the other version is running on a different node.

.. note:: The safest way to restart or replace nodes is by stopping a single node running the old version and starting a node running the new version as a sequence of operations, in order to avoid a situation in which most nodes have been stopped, and new nodes will not be able to join since it would be impossible to reach a majority of nodes agreeing to accept new nodes (this restriction is imposed by the consensus algorithm).

Accepting Recovery
------------------

Once the public recovered network has been established by operators (see :ref:`operators/recovery:Establishing a Recovered Public Network`), members are allowed to vote to confirm that the configuration of the new network is suitable to complete the recovery procedure.

The first member proposes to recover the network, passing the sealed network secrets file to the new network:

.. code-block:: bash

    $ memberclient --rpc-address node2_rpc_ip:node2_rpc_port --cert member1_cert.pem --privk member1_privk.pem --ca /path/to/new/network/certificate accept_recovery --sealed-secrets /path/to/sealed/secrets/file
    {"commit":100,"global_commit":99,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

    $ memberclient --rpc-address node2_rpc_ip:node2_rpc_port --cert member2_cert.pem --privk member2_privk.pem --ca /path/to/new/network/certificate vote --accept --proposal-id 1
    {"commit":102,"global_commit":101,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --rpc-address node2_rpc_ip:node2_rpc_port --cert member3_cert.pem --privk member3_privk.pem --ca /path/to/new/network/certificate vote --accept --proposal-id 1
    {"commit":104,"global_commit":103,"id":0,"jsonrpc":"2.0","result":true,"term":2}

Once a :term:`quorum` of members have agreed to recover the network, the network secrets are unsealed and each node begins recovery of the private ledger entries.

.. note:: While all nodes are recovering the private ledger, no new transaction can be executed by the network.

.. mermaid::

    sequenceDiagram
        participant Members
        participant Users
        participant Node 2
        participant Node 3

        Members->>+Node 2: Propose recovery + sealed network secrets
        Node 2-->>Members: Proposal ID
        loop Wait until quorum
            Members->>+Node 2: Vote(s) for Proposal ID
        end
        Note over Node 2: Proposal completes successfully

        Note over Node 2: Reading Private Ledger...
        Note over Node 3: Reading Private Ledger...

        Note over Node 2: Part of Network
        Note over Node 3: Part of Network

        loop Business transactions
            Users->>+Node 2: JSON-RPC Request
            Node 2-->>Users: JSON-RPC Response
            Users->>+Node 3: JSON-RPC Request
            Node 3-->>Users: JSON-RPC Response
        end

Once the recovery of the private ledger on all the nodes that have joined the new network is complete, the ledger is fully recovered and users are able to continue issuing business transactions.

Rekeying Ledger
---------------

To limit the scope of key compromise, members of the consortium can refresh the key used to encrypt the ledger. For example, rekeying can be triggered by members when existing nodes are removed from the service.

.. code-block:: bash

    $ memberclient --rpc-address node2_rpc_ip:node2_rpc_port --cert member1_cert.pem --privk member1_privk.pem --ca /path/to/new/network/certificate rekey_ledger
    {"commit":100,"global_commit":99,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

    $ memberclient --rpc-address node2_rpc_ip:node2_rpc_port --cert member2_cert.pem --privk member2_privk.pem --ca /path/to/new/network/certificate vote --accept --proposal-id 1
    {"commit":102,"global_commit":101,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --rpc-address node2_rpc_ip:node2_rpc_port --cert member3_cert.pem --privk member3_privk.pem --ca /path/to/new/network/certificate vote --accept --proposal-id 1
    {"commit":104,"global_commit":103,"id":0,"jsonrpc":"2.0","result":true,"term":2}

Once the proposal is accepted (``"result":true``), all subsequent transactions (in this case, with a ``commit`` index greater than ``104``) will be encrypted with a fresh new ledger encryption key. This key is sealed to disk once the rekey transaction is globally committed.