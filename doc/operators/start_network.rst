Starting a New Network
======================

.. note:: Before creating a new network:

    - The :ref:`identity of the initial members of the consortium must be created <members/index:Governance>`.
    - The :ref:`constitution should have been agreed by the initial members <members/constitution:Constitution>`.

Starting the First Node
-----------------------

To create a new CCF network, the first node of the network should be invoked with the ``start`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --rpc-address <ccf-node-address>
    --node-address <ccf-node-to-node-address>
    --public-rpc-address <ccf-node-public-address>
    [--domain domain]
    --ledger-dir /path/to/ledger/dir
    --node-cert-file /path/to/node_certificate
    [--sig-max-tx number_of_transactions]
    [--sig-max-ms number_of_milliseconds]
    start
    --network-cert-file /path/to/network_certificate
    --network-enc-pubk-file /path/to/network_encryption_pubk
    --member-info /path/to/member1_cert,/path/to/member1_enc_pub
    [--member-info /path/to/member2_cert,/path/to/member2_enc_pub ...]
    --gov-script /path/to/lua/governance_script

CCF nodes can be started by using IP Addresses (both IPv4 and IPv6 are supported) or by specifying a fully qualified domain name. If an FQDN is used then ``--domain`` should be passed to the node at startup. Once a DNS has been setup it will be possible to connect to the node over TLS by using the node's domain name.

When starting up, the node generates its own key pair and outputs the certificate associated with its public key at the location specified by ``--node-cert-file``. The certificate of the freshly-created CCF network is also output at the location specified by ``--network-cert-file`` as well as the network encryption public key used by members during recovery via ``--network-enc-pubk-file``.

.. note:: The network certificate should be distributed to users and members to be used as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. When using curl, this is passed as the ``--cacert`` argument.

The certificates and recovery public keys of initial members of the consortium are specified via ``--member-info``. For example, if 3 members should be added to CCF, operators should specify ``--member-info member1_cert.pem,member1_enc_pubk.pem``, ``--member-info member2_cert.pem,member2_enc_pubk.pem``, ``--member-info member3_cert.pem,member3_enc_pubk.pem``.

The :term:`Constitution`, as defined by the initial members, should be passed via the ``--gov-script`` option.

The network is now in its opening state and new nodes can join the network. :ref:`members can add other members and users via governance <members/open_network:Opening a Network>`.

Network Identity
~~~~~~~~~~~~~~~~

The network certificate should be distributed to users and members to be used as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. When using curl, this is passed as the ``--cacert`` argument.

Virtual Mode
~~~~~~~~~~~~

To start a CCF node in `virtual` mode, operators should run ``$ cchost.virtual --enclave-file /path/to/virtual_enclave_library ...``.

.. warning:: Nodes started in virtual mode provide no security guarantees. They should never be used for production purposes.

PBFT
~~~~

To use the PBFT consensus protocol, pass ``--consensus pbft``. Please see :ref:`here <developers/consensus:Consensus Protocols>` for more information.

Signature Interval
~~~~~~~~~~~~~~~~~~

Transaction commit latency in a CCF network is primarily a function of signature frequency. A network emitting signatures more frequently will be able to commit transactions faster,
but will spend a larger proportion of its execution resources creating and verifying signatures. Setting signature frequency is a trade-off between transaction
latency and throughput.

Two options are provided to that end:

- ``--sig-max-tx``: maximum number of transactions between two signatures
- ``--sig-max-ms``: maximum time in milliseconds between two signatures.

Adding a New Node to the Network
--------------------------------

To add a new node to an existing opening network, other nodes should be started with the ``join`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --rpc-address <ccf-node-address>
    --node-address <ccf-node-to-node-address>
    --public-rpc-address <ccf-node-public-address>
    --ledger-dir /path/to/ledger/dir
    --node-cert-file /path/to/node_certificate
    join
    --network-cert-file /path/to/existing/network_certificate
    --target-rpc-address <another-ccf-node-address>

The joining node takes the certificate of the existing network to join via ``--network-cert-file`` and initiates an enclave-to-enclave TLS connection to an existing node of the network as specified by ``--target-rpc-address``.

If the network has not yet been opened by members (see :ref:`members/open_network:Opening the Network`), the joining node becomes part of the network immediately [#remote_attestation]_.

If the network has already been opened to users, members need to trust the joining node before it can become part of the network (see :ref:`members/common_member_operations:Trusting a New Node`).

.. note:: If starting up the network with PBFT enabled as the consensus protocol, be sure to add the ``--consensus pbft`` CLI argument when starting up the node. For more information on the provided consensus protocols please see :ref:`here <developers/consensus:Consensus Protocols>`

Using a Configuration File
--------------------------

``cchost`` can be started using a configuration file in TOML or INI format.

.. code-block:: ini

    # config.toml
    enclave-file = <enclave-file>
    enclave-type = debug
    consensus = raft
    rpc-address = <node-address>
    public-rpc-address = <node-public-address>
    node-address = <ccf-node-to-node-address>

    [<subcommand, one of [start, join, recover]>]
    network-cert-file = <network-cert-file-name>
    member-info = "<member_cert.pem>,<member_enc_pubk.pem>"
    gov-script = <gov-script-name>

.. code-block:: ini

    ; config.ini
    enclave-file = <enclave-file>
    enclave-type = debug
    consensus = raft
    rpc-address = <node-address>
    public-rpc-address = <node-public-address>
    node-address = <node-to-node-address>

    [<subcommand, one of [start, join, recover]>]
    network-cert-file = <network-cert-file-name>
    member-info = "<member_cert.pem>,<member_enc_pubk.pem>"
    gov-script = <gov-script-name>

To pass configuration files, use the ``--config`` option: ``./cchost --config=config.ini``. An error will be generated if the configuration file contains extra fields. Options in the configuration file will be read along with normal command line arguments. Additional information for configuration files in CLI11 can be found `here <https://cliutils.github.io/CLI11/book/chapters/config.html>`_.

Opening a Network to Users
--------------------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, :ref:`members should vote to open the network <members/open_network:Opening a Network>` to :term:`Users` via governance.

Summary diagram
---------------

Once a node is part of the network (started with either the ``start`` or ``join`` option), members are authorised to issue governance transactions and eventually open the network (see :ref:`members/open_network:Opening a Network`). Only then are users authorised to issue commands to CCF.

.. note:: After the network is open to users, members can still issue governance transactions to CCF (for example, adding new users or additional members to the consortium or updating the Lua app, when applicable). See :ref:`members/index:Governance` for more information about member governance.

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
            Members->>+Node 0: HTTP Request (any node)
            Node 0-->>Members: HTTP Response (any node)
        end

        Members->>+Node 0: Propose to open network (any node)
        Members->>+Node 0: Vote to open network (any node)
        Note over Node 0, Node 1: Proposal accepted, CCF open to users


        loop Business transactions
            Users->>+Node 0: HTTP Request (any node)
            Node 0-->>Users: HTTP Response (any node)
        end

.. rubric:: Footnotes

.. [#remote_attestation] When a new node joins an existing network, the network performs the remote attestation protocol by verifying the joining node's quote. It also checks that the version of the code running by the joining node is trusted by the consortium.