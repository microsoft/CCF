Catastrophic Recovery
=====================

For unexpected reasons, a significant number [#crash]_ of CCF nodes may become unavailable. In this catastrophic scenario, operators and members can recover transactions that were committed on the crashed service by starting a new network.

The recovery procedure consists of two phases:

1. Operators should retrieve one of the ledgers of the previous service and re-start one or several nodes in ``recover`` mode. The public transactions of the previous network are restored and the new network established.

2. After agreeing that the configuration of the new network is suitable, members should vote to accept to recover the network and once this is done, submit their recovery shares to initiate the end of the recovery procedure. See :ref:`here <members/accept_recovery:Accepting Recovery and Submitting Shares>` for more details.

.. note:: It is possible that the length of the ledgers of each node may differ slightly since some transactions may not have yet been fully replicated. It is preferable to use the ledger of the primary node before the service crashed.

.. note:: Before attempting to recover a network, it is recommended to make a copy of all available ledgers.

Establishing a Recovered Public Network
---------------------------------------

To initiate the first phase of the recovery procedure, one or several nodes should be started with the ``recover`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --node-address node_ip:node_port
    --rpc-address <ccf-node-address>
    --public-rpc-address <ccf-node-public-address>
    [--domain domain]
    --ledger-file /path/to/ledger/to/recover
    --node-cert-file /path/to/node_certificate
    recover
    --network-cert-file /path/to/network_certificate

Each node will then immediately restore the public entries of its ledger (``--ledger-file``). Because deserialising the public entries present in the ledger may take some time, operators can query the progress of the public recovery by calling ``getSignedIndex`` which returns the version of the last signed recovered ledger entry. Once the public ledger is fully recovered, the recovered node automatically becomes part of the public network, allowing other nodes to join the network.

.. note:: If more than one node were started in ``recover`` mode, the node with the highest signed index (as per the response to the ``getSignedIndex`` RPC) should be preferred to start the new network. Other nodes should be shutdown and new nodes restarted with the ``join`` option.

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
        Node 2-->>Node 3: Join network response

        Note over Node 3: Part of Public Network

Once operators have established a recovered public network, the existing members of the consortium :ref:`must vote to accept the recovery of the network and submit their recovery shares <members/accept_recovery:Accepting Recovery and Submitting Shares>`.

.. warning:: After recovery, the identity of the network has changed. The new network certificate ``networkcert.pem`` must be distributed to all existing and new users.

.. rubric:: Footnotes

.. [#crash] When using Raft as consensus algorithm, CCF tolerates up to `N/2 - 1` crashed nodes (where `N` is the number of nodes constituting the network) before having to perform the catastrophic recovery procedure. For example, in a 5-node network, no more than 2 nodes are allowed to fail.