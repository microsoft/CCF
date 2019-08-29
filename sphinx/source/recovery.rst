Catastrophic Recovery
=====================

For unexpected reasons, a significant number [#crash]_ of CCF nodes may become unavailable. In this catastrophic scenario, it is possible that the length of ledgers of each node may differ slightly since some transactions may not have yet been fully replicated.

.. note:: The current version of the recovery protocol relies on Intel SGX Sealing capability [#sealing]_.

However, one of the previous ledgers can be recovered and the execution of new business transactions continue if the following three conditions are met:

- At least one of the old nodes' CPU survived.
- The sealed network secret file (``sealed_secrets.<date>.<pid>``) associated with that CPU is available to a :term:`quorum` of members.
- One of the ledgers (preferably the ledger of the previous primary as it is likely to be the longest) is available.

The recovery protocol consists of two phases. First, the public transactions of the previous network are restored and the new network established. Then, after the members have agreed that the configuration of the new network is suitable, the sealed network secrets can be restored by a new set of trusted nodes and the previous private transactions recovered.

.. note:: Before attempting to recover a network, it is recommended to make a copy of all available ledgers and sealed secrets files.

Phase 1: Crash-fault tolerant public network
--------------------------------------------

To initiate the first phase of the recovery protocol, one or several nodes should be started with the ``recover`` option:

.. code-block:: bash

    $ cchost --enclave-file /path/to/enclave_library --enclave-type debug --node-address node_ip:node_port
    --rpc-address rpc_ip:rpc_port --public-rpc-address public_rpc_ip:public_rpc_port
    --ledger-file /path/to/ledger/to/recover
    --node-cert-file /path/to/node_certificate --quote-file /path/to/quote
    recover --network-cert-file /path/to/network_certificate

Each node will then immediately restore the public entries of its ledger (``--ledger-file``). Because deserialising the public entries present in the ledger may take some time, operators can query the progress of the public recovery by running the ``getSignedIndex`` JSON-RPC which returns the version of the last signed recovered ledger entry. Once the public ledger is fully recovered, the recovered node automatically becomes part of the public network, allowing other nodes to join the network.

.. note:: If more than one node were started in ``recover`` mode, the node with the highest signed index (as per the response to the ``getSignedIndex`` JSON-RPC) should be preferred to start the new network. Other nodes should be shutdown and be restarted with the ``join`` option.

Similarly to the normal join protocol (see :ref:`Joining an existing network`), other nodes are then able to join the network.

.. mermaid::

    sequenceDiagram
        participant Operators
        participant Members
        participant Node 2
        participant Node 3

        Operators->>+Node 2: cchost --rpc-address=ip2:port2 --ledger-file=ledger0 recover
        Node 2-->>Operators: Network Certificate
        Note over Node 2: Reading Public Ledger...

        Members->>+Node 2: getSignedIndex
        Node 2-->>Members: {"signed_index": 50, "state": "readingPublicLedger"}
        Note over Node 2: Finished Reading Public Ledger, now Part of Public Network
        Members->>Node 2: getSignedIndex
        Node 2-->>Members: {"signed_index": 243, "state": "partOfPublicNetwork"}

        Note over Operators, Node 2: Operators select Node 2 to start the new network

        Operators->>+Node 3: cchost join --network-cert-file=Network Certificate --target-rpc-address=ip2:port2
        Node 3->>+Node 2: Join network (over TLS)
        Node 2-->>Node 3: Network Secrets (over TLS)

        Note over Node 3: Part of Public Network

Phase 2: Unsealing secrets and recovering private transactions
--------------------------------------------------------------

Once the public crash-fault tolerant network is established, members are allowed to vote to confirm that the configuration of the new network is suitable to complete the recovery protocol. The first member proposes to recover the network, passing the sealed network secrets file to the new network:

.. code-block:: bash

    $ memberclient --cert /path/to/member1/certificate --privk /path/to/member1/private/key
    --rpc-address node2_rpc_ip:node2_rpc_port --ca /path/to/new/network/certificate
    accept_recovery --sealed-secrets /path/to/sealed/secrets/file

If successful, this commands returns the proposal id that can be used by other members to submit their votes:

.. code-block:: bash

    $ memberclient --cert /path/to/member2/certificate --privk /path/to/member2/private/key
    --rpc-address node2_rpc_ip:node2_rpc_port --ca /path/to/new/network/certificate
    vote --accept --proposal-id proposal_id

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

.. warning:: After recovery, the identity of the network has changed. The new network certificate ``networkcert.pem`` returned in :ref:`Phase 1: Crash-fault tolerant public network` needs to be distributed to all existing and new users.

.. rubric:: Footnotes

.. [#crash] When using Raft as consensus algorithm, CCF tolerates up to `N/2 - 1` crashed nodes (where `N` is the number of nodes constituting the network) before having to perform catastrophic recovery. For example, in a 5-node network, no more than 2 nodes are allowed to fail.

.. [#sealing] `Intel SGX Sealing <https://software.intel.com/en-us/blogs/2016/05/04/introduction-to-intel-sgx-sealing>`_.
