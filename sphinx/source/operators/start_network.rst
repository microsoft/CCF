Starting a New Network
======================

.. note:: Before creating a new network:

    - The :ref:`identity of the initial members of the consortium must be created <members/index:Member Governance>`.
    - The :ref:`constitution should have been agreed by the initial members <members/constitution:Constitution>`.

Starting the First Node
-----------------------

To create a new CCF network, the first node of the network should be started with the ``start`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --enclave-type debug
    --node-address node_ip:node_port
    --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port
    --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate
    --quote-file /path/to/quote
    start
    --network-cert-file /path/to/network_certificate
    --member-cert /path/to/member1_cert
    [--member-cert /path/to/member2_cert ...]
    --gov-script /path/to/lua/governance_script

.. note:: To start a CCF node in `virtual` mode, operators should run ``$ cchost.virtual --enclave-file /path/to/virtual_enclave_library ...``

When starting up, the node generates its own key pair and outputs the certificate associated with its public key at the location specified by ``--node-cert-file``. A quote file, required for remote attestation, is also output at the location specified by ``--quote-file``. The certificate of the freshly-created CCF network is also output at the location specified by ``--network-cert-file``.

.. note:: The network certificate should be distributed to users and members to be used as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. For the ``client`` and ``memberclient`` utilities, ``--ca /path/to/network_certificate`` should always be specified.

The certificates of initial members of the consortium are specified via ``--member-cert``. For example, if 3 members (``member1_cert.pem``, ``member2_cert.pem`` and ``member3_cert.pem``) should be added to CCF, operators should specify ``--member-cert member1_cert.pem --member-cert member2_cert.pem --member-cert member3_cert.pem``.

The :term:`constitution`, as defined by the initial members, should be passed via the ``--gov-script`` option.

The network is now in its opening state and any new nodes can join the network without being trusted by members.

.. note:: Once a CCF network is started, :ref:`members can add other members and users via governance <members/open_network:Opening a Network>`.

Adding a New Node to the Network
--------------------------------

To add a new node to an existing opening network, other nodes should be started with the ``join`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --enclave-type debug
    --node-address node_ip:node_port
    --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port
    --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate
    --quote-file /path/to/quote
    join
    --network-cert-file /path/to/existing/network_certificate
    --target-rpc-address target_rpc_ip:target_rpc_port

The joining node takes the certificate of the existing network to join via ``--network-cert-file`` and initiates an enclave-to-enclave TLS connection to an existing node of the network as specified by ``--target-rpc-address``.

If the network has not yet been opened by members (see :ref:`members/open_network:Opening the Network`), the joining node becomes part of the network immediately [#remote_attestation]_.

If the network has already been opened to users, members need to trust the joining node before it can become part of the network (see :ref:`members/common_member_operations:Trusting a New Node`).

.. note:: When starting up the network or when joining an existing network, the network secrets required to decrypt the ledger are sealed and written to a file so that the network can later be recovered. See :ref:`operators/recovery:Catastrophic Recovery` for more details on how to recover a crashed network.
.. note:: CCF nodes can be started by using IP Addresses (both IPv4 and IPV6 are supported) or by specifying domain names. If domain names are to be used then ``--domain=<node domain name>`` should be passed to the node at startup. Once a DNS has been setup it will then be possible to connect to the node over TLS by using the node's domain name.

Opening a Network to Users
--------------------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, :ref:`members should vote to open the network <members/open_network:Opening a Network>` to :term:`users` via governance.

Summary diagram
---------------

Once a node is part of the network (started with either the ``start`` or ``join`` option), members are authorised to issue governance transactions and eventually open the network (see :ref:`members/open_network:Opening a Network`). Only then are users authorised to issue JSON-RPC transactions to CCF.

.. note:: After the network is open to users, members can still issue governance transactions to CCF (for example, adding new users or additional members to the consortium or updating the Lua app, when applicable). See :ref:`members/index:Member Governance` for more information about member governance.

The following diagram summarises the steps required to bootstrap a CCF network:

.. mermaid::

    sequenceDiagram
        participant Operators
        participant Members
        participant Users
        participant Node 0
        participant Node 1

        Operators->>+Node 0: cchost start --rpc-address=ip0:port0
        Node 0-->>Operators: Network Certificate
        Note over Node 0: Part Of Network

        Operators->>+Node 1: cchost join --network-cert-file=Network Certificate --target-rpc-address=ip0:port0

        Node 1->>+Node 0: Join network (over TLS)
        Node 0-->>Node 1: Network Secrets (over TLS)

        Note over Node 1: Part Of Network

        loop Governance transactions (e.g. adding a user)
            Members->>+Node 0: JSON-RPC Request (any node)
            Node 0-->>Members: JSON-RPC Response (any node)
        end

        Members->>+Node 0: Propose to open network (any node)
        Members->>+Node 0: Vote to open network (any node)
        Note over Node 0, Node 1: Proposal accepted, CCF open to users


        loop Business transactions
            Users->>+Node 0: JSON-RPC Request (any node)
            Node 0-->>Users: JSON-RPC Response (any node)
        end

.. rubric:: Footnotes

.. [#remote_attestation] When a new node joins an existing network, the network performs the remote attestation protocol by verifying the joining node's quote. It also checks that the version of the code running by the joining node is trusted by the consortium.