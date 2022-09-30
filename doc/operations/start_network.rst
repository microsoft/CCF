Running a CCF Service
=====================

.. note:: Before creating a new network:

    - The :ref:`identity of the initial members of the consortium must be created <governance/adding_member:Generating Member Keys and Certificates>`.
    - The :ref:`constitution should have been agreed by the initial members <overview/governance:Governance>`.

Starting the First Node
-----------------------

To create a new CCF network, the first node of the network should be started with the ``start`` option:

.. code-block:: bash

    $ cchost --config /path/to/config/file

.. mermaid::

    graph LR;
        Uninitialized-- config -->Initialized;
        Initialized-- start -->PartOfNetwork;

The unique identifier of a CCF node is the hex-encoded string of the SHA-256 digest of the public key contained in its identity certificate (e.g. ``50211327a77fc16dd2fba8fae5fffac3df909fceeb307cf804a4125ae2679007``). This unique identifier should be used by operators and members to refer to this node with CCF (for example, when :ref:`governance/common_member_operations:Trusting a New Node`).

CCF nodes can be started by using IP Addresses (both IPv4 and IPv6 are supported) or by specifying a fully qualified domain name. If an FQDN is used then a ``dNSName`` subject alternative name should be specified as part of the ``node_certificate.subject_alt_names`` configuration entry. Once a DNS has been setup it will be possible to connect to the node over TLS by using the node's domain name.

When starting up, the node generates its own key pair and outputs the unendorsed certificate associated with its public key at the location specified by the ``node_certificate_file`` configuration entry. The certificate of the freshly-created CCF network is also output at the location specified by the ``service_certificate_file`` configuration entry.

.. note:: The service certificate should be distributed to users and members to be used as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. When using ``curl``, this is passed as the ``--cacert`` argument.

The initial constitution scripts, member certificates, public encryption keys and data files as well as the initial service configuration should be set in the :ref:`operations/configuration:``start``` section of the JSON configuration.

Once the first node is started, the network will be in its opening state and new nodes can join the network.

Adding a New Node to the Network
--------------------------------

To add a new node to an existing opening network, other nodes should be started with the ``join`` option:

.. code-block:: bash

    $ cchost --config /path/to/config/file

.. mermaid::

    graph LR;
        Uninitialized-- config -->Initialized;
        Initialized-- join -->Pending;
        Pending-- poll status -->Pending;
        Pending-- trusted -->PartOfNetwork;

The joining node takes the certificate of the existing network to join via ``service_certificate_file`` configuration entry and initiates an enclave-to-enclave TLS connection to an existing node of the network as specified by ``join.target_rpc_address`` configuration entry.

The join configuration option should be set in the :ref:`operations/configuration:``join``` section of the JSON configuration.

A new node can only join an existing CCF network if its SGX quote is valid  [#remote_attestation]_. and runs an enclave application that is :ref:`trusted by the consortium <governance/common_member_operations:Updating Code Version>`.

If the network has not yet been opened by members (see :ref:`governance/open_network:Opening the Network`), the joining node becomes part of the network immediately. Otherwise, if the network has already been opened to users, members need to trust the joining node before it can become part of the network and participate in the consensus (see :ref:`governance/common_member_operations:Trusting a New Node`).

The ``Pending`` joining node automatically polls the service (interval configurable via ``join.retry_timeout`` configuration entry) until the members have successfully transitioned the node to the ``Trusted`` state. It is only then that the joining node transitions to the ``PartOfNetwork`` state and starts updating its ledger.

.. tip:: After the node has been trusted by members, operators should poll the :http:GET:`/node/state` endpoint on the newly added node, using the node's self-signed certificate as TLS CA, until the ``{"state": "PartOfNetwork"}`` is reported. This status confirms that the replication of the ledger has started on this node.

.. note:: To accelerate the joining procedure, it is possible for new nodes to join from a snapshot. More information on snapshots :ref:`here <operations/ledger_snapshot:Join/Recover From Snapshot>`.

The following diagram summarises the steps that operators and members should follow to add a new node to an open CCF service, and wait for it to be trusted by the consortium and in state ``PartOfNetwork``:

.. mermaid::

    sequenceDiagram
        participant Operators
        participant Members
        participant Node 0
        participant Node 1

        Note over Node 0: Already "PartOfNetwork" (rpc-address=ip0:port0)

        Operators->>+Node 1: cchost join (config: service_certificate_file=Service Certificate target_rpc_address=ip0:port0)

        Node 1->>+Node 0: Join request (includes quote)
        Node 0->>+Node 0: Verify Node 1 attestation
        Node 0-->>Node 1: "Pending" state

        loop Node 1 polls Node 0 (as per join.retry_timeout configuration entry)
            Node 1->>+Node 0: Poll for "Trusted" state
            Node 0-->>-Node 1: "Pending" state
        end

        Operators->>+Node 1: Poll GET /node/state for "PartOfNetwork" (using self-signed certificate as CA)
        Node 1-->>-Operators: "Pending" state

        Members->>+Node 0: transition_node_to_trusted proposal for Node 1 and votes
        Node 0-->>-Members: Proposal Accepted

        Operators->>+Node 1: Poll GET /node/state for "PartOfNetwork" (using self-signed certificate as CA)
        Node 1-->>-Operators: "Pending" state

        Node 1->>+Node 0: Poll for "Trusted" state
        Node 0-->>-Node 1: "Trusted" state (includes ledger secrets and service private key)

        Note over Node 1: State: "PartOfNetwork" <br/> Ledger replication started <br/> Application open to users

        loop Node 1 ledger replication
            Node 0->>+Node 1: Ledger replication
        end

        Operators->>+Node 1: Poll GET /node/state for "PartOfNetwork" (using self-signed certificate as CA)
        Node 1-->>-Operators: "PartOfNetwork" state

        loop Node 1 ledger replication
            Node 0->>+Node 1: Ledger replication
        end

        Node 1->>+Node 1: Observe own addition to store <br> Endorse TLS with service private key

        Note over Operators: Operators monitor progress of ledger replication
        Operators->>+Node 1: Poll GET /node/commit
        Node 1-->>-Operators: "commit": ...

Opening a Network to Users
--------------------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, :ref:`members should vote to open the network <governance/open_network:Opening a Network>` to :term:`Users` via governance.

Virtual Mode
------------

To run a CCF node on a system without hardware TEE support, or to debug an application, a ``virtual`` enclave should be used.
To start a CCF node in ``virtual`` mode, the JSON configuration file should specify the path of a ``*.virtual.so`` enclave library and ``enclave.type`` should be set to ``"virtual"``.

.. warning:: Nodes started in virtual mode provide no security guarantees. They should never be used for production purposes.

Node and Service Data
---------------------

To be able to better identify a specific service and its nodes, operators can specify arbitrary JSON data to attach to each service/node:

- The optional :ref:`operations/configuration:``node_data_json_file``` configuration entry specifies the path to a JSON file containing node-specific information, e.g. the pod identifier in a Kubernetes deployment. This data is recorded in the :ref:`audit/builtin_maps:``nodes.info``` table and accessible via the :http:GET:`/node/network/nodes` endpoint.
- The optional :ref:`operations/configuration:``service_data_json_file``` configuration entry specifies the path to a JSON file containing service-specific information, e.g. the timestamp at which the service started or the cluster identifier in a Kubernetes deployment. This data is recorded in the :ref:`audit/builtin_maps:``service.info``` table and accessible via the :http:GET:`/node/network` endpoint.

.. rubric:: Footnotes

.. [#remote_attestation] When a new node joins an existing network, the network performs the remote attestation protocol by verifying the joining node's quote. It also checks that the version of the code running by the joining node is trusted by the consortium.
