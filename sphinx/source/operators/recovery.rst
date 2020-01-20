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

Establishing a Recovered Public Network
---------------------------------------

To initiate the first phase of the recovery protocol, one or several nodes should be started with the ``recover`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --enclave-type debug
    --node-address node_ip:node_port
    --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port
    --ledger-file /path/to/ledger/to/recover
    --node-cert-file /path/to/node_certificate
    --quote-file /path/to/quote
    recover
    --network-cert-file /path/to/network_certificate

Each node will then immediately restore the public entries of its ledger (``--ledger-file``). Because deserialising the public entries present in the ledger may take some time, operators can query the progress of the public recovery by running the ``getSignedIndex`` JSON-RPC which returns the version of the last signed recovered ledger entry. Once the public ledger is fully recovered, the recovered node automatically becomes part of the public network, allowing other nodes to join the network.

.. note:: If more than one node were started in ``recover`` mode, the node with the highest signed index (as per the response to the ``getSignedIndex`` JSON-RPC) should be preferred to start the new network. Other nodes should be shutdown and be restarted with the ``join`` option.

Similarly to the normal join protocol (see :ref:`operators/start_network:Adding a New Node to the Network`), other nodes are then able to join the network.

.. mermaid::

    sequenceDiagram
        participant Operators
        participant Node 2
        participant Node 3

        Operators->>+Node 2: cchost --rpc-address=ip2:port2 --ledger-file=ledger0 recover
        Node 2-->>Operators: Network Certificate
        Note over Node 2: Reading Public Ledger...

        Operators->>+Node 2: getSignedIndex
        Node 2-->>Operators: {"signed_index": 50, "state": "readingPublicLedger"}
        Note over Node 2: Finished Reading Public Ledger, now Part of Public Network
        Operators->>Node 2: getSignedIndex
        Node 2-->>Operators: {"signed_index": 243, "state": "partOfPublicNetwork"}

        Note over Operators, Node 2: Operators select Node 2 to start the new network

        Operators->>+Node 3: cchost join --network-cert-file=Network Certificate --target-rpc-address=ip2:port2
        Node 3->>+Node 2: Join network (over TLS)
        Node 2-->>Node 3: Network Secrets (over TLS)

        Note over Node 3: Part of Public Network

Once operators have established a recovered public network, the existing members of the consortium :ref:`must vote to accept the recovery of the network <members/common_member_operations:Accepting Recovery>`.

.. warning:: After recovery, the identity of the network has changed. The new network certificate ``networkcert.pem`` must be distributed to all existing and new users.

.. rubric:: Footnotes

.. [#crash] When using Raft as consensus algorithm, CCF tolerates up to `N/2 - 1` crashed nodes (where `N` is the number of nodes constituting the network) before having to perform catastrophic recovery. For example, in a 5-node network, no more than 2 nodes are allowed to fail.

.. [#sealing] `Intel SGX Sealing <https://software.intel.com/en-us/blogs/2016/05/04/introduction-to-intel-sgx-sealing>`_.
