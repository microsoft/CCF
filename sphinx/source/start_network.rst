Starting up a network
=====================

Starting up nodes
~~~~~~~~~~~~~~~~~

To start up a network, operators should start up each node separately by running:

.. code-block:: bash

    $ cchost --enclave-file=/path/to/application --raft-host=raft_ip --raft-port=raft_port
    --tls-host=tls_ip --tls-pubhost=tls_public_ip --tls-port=tls_port --ledger-file=ledger_file
    --node-cert-file=/path/to/node_certificate --quote-file=/path/to/quote

    <Some log messages confirming that the enclave has been created>

When starting up, each node generates its own key pair and outputs the certificate associated with the public key at the location specified by ``--node-cert``. A quote file, required for remote attestation when this node joins the network, is also output at the location specified by ``--quote-file``.

Configuring the initial state of the network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once the initial set of nodes is running, the ``nodes.json`` file specifying the configuration of the original network should be created. For example, for a network of two nodes, the ``nodes.json`` file will be:

.. code-block:: bash

    $ cat nodes.json
    [
        {
            "pubhost": "tls_public_ip0",
            "cert": [<output node0 cert bytes>],
            "host": "raft/tls_ip0",
            "quote": [<output quote0 bytes>],
            "status": 0,
            "raftport": "raft_port0",
            "tlsport": "tls_port0"
        },
        {
            "pubhost": "tls_public_ip1",
            "cert": [<output node1 cert bytes>],
            "host": "tls_ip1",
            "quote": [<output quote1 bytes>],
            "status": 0,
            "raftport": "raft_port1",
            "tlsport": "tls_port1"
        }
    ]

Then, certificates for members and users can be created to allow secure TLS communication between the clients and the enclaves of each node. For example, for two members and one user, you should run:

.. code-block:: bash

    $ genesisgenerator cert --name=member1
    $ genesisgenerator cert --name=member2
    $ genesisgenerator cert --name=user1

Finally, the genesis transaction (``tx0``), containing the initial state of the network, including the initial set of nodes, users and members certificates and governance scripts, can be created:

.. code-block:: bash

    $ genesisgenerator tx --members=member*cert.pem --users=user*cert.pem --nodes=nodes.json --gov-script=src/runtime_config/gov.lua --tx0=tx0 --start-json=startNetwork.json

This command also generates the ``startNetwork.json`` RPC file required to start up the network.

Starting up the network
~~~~~~~~~~~~~~~~~~~~~~~

Once the initial nodes are running and the initial state of the network is ready to deploy, the network can be started by one of the members:

.. code-block:: bash

    $ client --host=<node0_ip> --port=<node0_tlsport> startnetwork --server-cert=<node0_cert> --req=startNetwork.json

When executing the ``startNetwork.json`` RPC request, the target node deserialises the genesis transaction and immediately becomes the Raft leader of the new single-node network. Business transactions can then be issued by users and will commit immediately.

Adding nodes to the network
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once a network has been started on one node, assuming that this node remains leader of the Raft network, join network RPC files can be generated for all others nodes defined in the initial state of the network (``nodes.json``):

.. code-block:: bash

    $ genesisgenerator joinrpc --network-cert=networkcert.pem --host=<node0_ip> --port=<node0_tlsport> --join-json=joinNetwork.json

Once done, each additional node (here, node 1) can join the existing network by running the following command:

.. code-block:: bash

    $ client --host=<node1_ip> --port=<node1_tlsport> joinnetwork --server-cert=<node1_cert> --req=joinNetwork.json

When executing the ``joinNetwork.json`` RPC, the target node initiates an enclave-to-enclave TLS connection to the network leader to retrieve the network secrets required to decrypt the serialised replicated transactions. Once the join protocol completes, the new node becomes a follower of the Raft network and starts replicating transactions executed by the leader.

.. note:: When starting up the network or when a node joins an existing network, the network secrets required to decrypt the ledger are sealed to disc so that the network can later be recovered. See :ref:`Catastrophic Recovery` for more details on how to recover a crashed network.


.. mermaid::

    sequenceDiagram
        participant Members
        participant Users
        participant Leader
        participant Follower

        Members->>+Leader: start network
        Leader->>+Leader: New network secrets
        Leader-->>Members: start network success

        Note over Leader: Part of Private Network

        Members->>+Follower: join network
        Follower->>+Leader: join network (over TLS)
        Follower-->>Members: join network response
        Leader->>+Follower: Network Secrets (over TLS)

        Note over Follower: Part of Private Network

        loop Business transactions
            Users->>+Leader: Tx
            Leader-->>Users: response
            Leader->>+Follower: Serialised Tx
        end


