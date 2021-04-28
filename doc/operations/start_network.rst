Running a CCF Service
=====================

.. note:: Before creating a new network:

    - The :ref:`identity of the initial members of the consortium must be created <governance/adding_member:Generating Member Keys and Certificates>`.
    - The :ref:`constitution should have been agreed by the initial members <overview/constitution:Constitution>`.

Starting the First Node
-----------------------

To create a new CCF network, the first node of the network should be started with the ``start`` option:

.. code-block:: bash

    $ cchost
    --enclave-file /path/to/enclave_library
    --rpc-address <ccf-node-address>
    --node-address <ccf-node-to-node-address>
    --public-rpc-address <ccf-node-public-address>
    [--domain domain]
    --ledger-dir /path/to/ledger/dir
    --node-cert-file /path/to/node_certificate
    start
    --network-cert-file /path/to/network_certificate
    --member-info /path/to/member1_cert[,/path/to/member1_enc_pubk[,/path/to/member1_data]]
    [--member-info /path/to/member2_cert[,/path/to/member2_enc_pubk[,/path/to/member2_data]] ...]
    --constitution /path/to/javascript/constitution_module.js

CCF nodes can be started by using IP Addresses (both IPv4 and IPv6 are supported) or by specifying a fully qualified domain name. If an FQDN is used then ``--san dNSName:<sub.domain.tld>`` should be passed to the node at startup. Once a DNS has been setup it will be possible to connect to the node over TLS by using the node's domain name.

When starting up, the node generates its own key pair and outputs the unendorsed certificate associated with its public key at the location specified by ``--node-cert-file``. The certificate of the freshly-created CCF network is also output at the location specified by ``--network-cert-file``.

The unique identifier of a CCF node is the hex-encoded string of the SHA-256 digest the public key contained in its identity certificate (e.g. ``50211327a77fc16dd2fba8fae5fffac3df909fceeb307cf804a4125ae2679007``). This unique identifier should be used by operators and members to refer to this node with CCF (for example, when :ref:`governance/common_member_operations:Trusting a New Node`).

.. note:: The network certificate should be distributed to users and members to be used as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. When using ``curl``, this is passed as the ``--cacert`` argument.

The certificates, encryption public keys and member data of initial members of the consortium are specified via ``--member-info``. For example:

- A recovery member with member data: ``--member-info member_cert.pem,member_enc_pubk.pem,member_data.json``
- A recovery member with no member data: ``--member-info member_cert.pem,member_enc_pubk.pem``
- A non-recovery member with member data: ``--member-info member_cert.pem,,member_data.json`` (note the empty public encryption key path "``,,``")
- A non-recovery member with no member data: ``--member-info member_cert.pem``

The :term:`Constitution`, as defined by the initial members, should be passed via one or multiple ``--constitution`` option(s).

Once the first node is started, the network will be in its opening state and new nodes can join the network.

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
    [--snapshot-dir /path/to/ledger/dir]
    [--read-only-ledger-dir /path/to/read/only/ledger/dir]
    join
    --network-cert-file /path/to/existing/network_certificate
    --target-rpc-address <another-ccf-node-address>
    [--join-timer <join-retry-interval-ms>]

The joining node takes the certificate of the existing network to join via ``--network-cert-file`` and initiates an enclave-to-enclave TLS connection to an existing node of the network as specified by ``--target-rpc-address``.

A new node can only join an existing CCF network if its SGX quote is valid  [#remote_attestation]_. and runs an enclave application that is :ref:`trusted by the consortium <governance/common_member_operations:Updating Code Version>`.

If the network has not yet been opened by members (see :ref:`governance/open_network:Opening the Network`), the joining node becomes part of the network immediately.

Otherwise, if the network has already been opened to users, members need to trust the joining node before it can become part of the network and participate in the consensus (see :ref:`governance/common_member_operations:Trusting a New Node`).

The ``Pending`` joining node will automatically poll the service (interval configurable via ``--join-timer`` option) until the members have successfully transitioned the node to the ``Trusted`` state. It is only then that the joining node will transition to the ``PartOfNetwork`` state and start updating its ledger.

.. tip:: After the node has been trusted by members, operators should poll the ``/node/state`` endpoint on the newly added node until the ``{"state": "PartOfNetwork"}`` is reported. This status confirms that the replication of the ledger has started on this node.

.. note:: To accelerate the joining procedure, it is possible for new nodes to join from a snapshot. More information on snapshots :ref:`here <operations/ledger_snapshot:Join/Recover From Snapshot>`.

The following diagram summarises the steps that operators and members should follow to add a new node to an open CCF service, and wait for it to be trusted by the consortium and in state ``PartOfNetwork``:

.. mermaid::

    sequenceDiagram
        participant Operators
        participant Members
        participant Node 0
        participant Node 1

        Note over Node 0: Already "PartOfNetwork" (rpc-address=ip0:port0)

        Operators->>+Node 1: cchost join --network-cert-file=Network Certificate --target-rpc-address=ip0:port0

        Node 1->>+Node 0: Join request (includes quote)
        Node 0->>+Node 0: Verify Node 1 attestation
        Node 0-->>Node 1: "Pending" state

        loop Node 1 polls Node 0 (as per --join-timer option)
            Node 1->>+Node 0: Poll for "Trusted" state
            Node 0-->>-Node 1: "Pending" state
        end

        Operators->>+Node 1: Poll /node/state for "PartOfNetwork"
        Node 1-->>-Operators: "Pending" state

        Members->>+Node 0: transition_node_to_trusted proposal for Node 1 and votes
        Node 0-->>-Members: Proposal Accepted

        Operators->>+Node 1: Poll /node/state for "PartOfNetwork"
        Node 1-->>-Operators: "Pending" state

        Node 1->>+Node 0: Poll for "Trusted" state
        Node 0-->>-Node 1: "Trusted" state (includes ledger secrets and service private key)

        Node 1->>+Node 1: Endorse TLS with service private key

        Note over Node 1: State: "PartOfNetwork" <br/> Ledger replication started <br/> Application open to users

        loop Node 1 ledger replication
            Node 0->>+Node 1: Ledger replication
        end

        Operators->>+Node 1: Poll /node/state for "PartOfNetwork"
        Node 1-->>-Operators: "PartOfNetwork" state

        loop Node 1 ledger replication
            Node 0->>+Node 1: Ledger replication
        end

        Note over Operators: Operators monitor progress of ledger replication
        Operators->>+Node 1: Poll /node/commit
        Node 1-->>-Operators: "commit": ...


Opening a Network to Users
--------------------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, :ref:`members should vote to open the network <governance/open_network:Opening a Network>` to :term:`Users` via governance.

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
    member-info = "<member_cert.pem>,<member_enc_pubk.pem>[,<member_data.json>]"
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
    member-info = "<member_cert.pem>,<member_enc_pubk.pem>[,<member_data.json>]"
    gov-script = <gov-script-name>

To pass configuration files, use the ``--config`` option: ``./cchost --config=config.ini``. An error will be generated if the configuration file contains extra fields. Options in the configuration file will be read along with normal command line arguments. Additional information for configuration files in CLI11 can be found `here <https://cliutils.github.io/CLI11/book/chapters/config.html>`_.

Virtual Mode
------------

To start a CCF node in `virtual` mode, operators should use the `virtual` variants of the ``cchost`` binary and enclave application:

.. code-block:: bash

    $ cchost.virtual --enclave-file /path/to/virtual_enclave_library [args]

.. warning:: Nodes started in virtual mode provide no security guarantees. They should never be used for production purposes.

Signature Interval
------------------

Transaction commit latency in a CCF network is primarily a function of signature frequency. A network emitting signatures more frequently will be able to commit transactions faster, but will spend a larger proportion of its execution resources creating and verifying signatures. Setting signature frequency is a trade-off between transaction latency and throughput.

Two options are provided to that end:

- ``--sig-tx-interval``: number of transactions between two signatures
- ``--sig-ms-interval``: time in milliseconds between two signatures

.. note:: These options specify the intervals at which the generation of signature transactions is `triggered`. However, because of the parallel execution of transactions, the actual intervals between signature transactions may be slightly larger.

.. rubric:: Footnotes

.. [#remote_attestation] When a new node joins an existing network, the network performs the remote attestation protocol by verifying the joining node's quote. It also checks that the version of the code running by the joining node is trusted by the consortium.
