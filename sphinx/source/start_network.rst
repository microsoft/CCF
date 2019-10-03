Starting up a network
=====================

This page describes how operators and the members of the consortium can bootstrap a new CCF network.

.. note:: When building CCF from source, all required artefacts (e.g. ``cchost``, enclave libraries such as ``libloggingenc.so.signed``) can be found in the ``build`` directory created before running `cmake`.

Create a new network
--------------------

To start up a network, the first node of the network should be started with the ``start`` option:

.. code-block:: bash

    $ cchost --enclave-file /path/to/enclave_library --enclave-type debug
    --node-address node_ip:node_port --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate --quote-file /path/to/quote
    start --network-cert-file /path/to/network_certificate --gov-script /path/to/lua/governance_script
    --member-certs member_certificates_glob

When starting up, the node generates its own key pair and outputs the certificate associated with its public key at the location specified by ``--node-cert-file``. A quote file, required for remote attestation, is also output at the location specified by ``--quote-file``. The certificate of the freshly-created CCF network is also output at the location specified by ``--network-cert-file``.

.. note:: The network certificate should be used by users and members as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. For the ``client`` and ``memberclient`` utilities, ``--ca /path/to/network_certificate`` should always be specified.

The :ref:`governance` rules are defined as a Lua script passed via the ``--gov-script`` option. For example, a default set of `governance rules <https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov.lua>`_ can be used to define a majority of members as the :term:`quorum` of the consortium.

The identities of members are specified as a `glob pattern <https://en.wikipedia.org/wiki/Glob_(programming)>`_ via the ``--member-certs`` option. For example, if 3 members (``member1_cert.pem``, ``member2_cert.pem`` and ``member3_cert.pem``) should be added to CCF, operators should specify ``--member-certs member*_cert.pem``.

.. note:: Once a CCF network is started, members can add other members and users via governance. See :ref:`Submitting a new proposal`.

When CCF is used to run a custom Lua application, the starting node should also be started with the ``--app-script /path/to/lua/application_script`` (see the `samples folder <https://github.com/microsoft/CCF/tree/master/samples/apps>`_ for example of Lua applications).

Add a new node to an opening network
------------------------------------

To add a new node to an existing opening network, other nodes should be started with the ``join`` option:

.. code-block:: bash

    $ cchost --enclave-file /path/to/enclave_library --enclave-type debug
    --node-address node_ip:node_port --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate --quote-file /path/to/quote
    join --network-cert-file /path/to/existing/network_certificate --target-rpc-address target_rpc_ip:target_rpc_port

The joining node takes the certificate of the existing network to join via ``--network-cert-file`` and initiates an enclave-to-enclave TLS connection to an existing node of the network as specified by ``--target-rpc-address``. Once the join protocol [#remote_attestation]_ completes, the joining node becomes part of the network as a backup (see :ref:`Ledger replication` for more details on consensus protocols).

.. note:: When starting up the network or when joining an existing network, the network secrets required to decrypt the ledger are sealed and written to a file so that the network can later be recovered. See :ref:`Catastrophic Recovery` for more details on how to recover a crashed network.

Open a network to users
-----------------------

Add users
~~~~~~~~~

Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to users. First, the certificates of trusted users should be registered in CCF via the member governance interface. For example, the first member may decide to make a proposal to add a new user (here, ``user_cert`` is the PEM certificate of the user -- see :ref:`Cryptography` for a list of supported algorithms):

.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert add_user --user_cert user_cert
    {"commit":4,"global_commit":3,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":0},"term":2}

Other members are then allowed to vote for the proposal, using the proposal ID returned to the proposer member (here ``0``, as per ``"result":{"completed":false,"id":0}``).

.. code-block:: bash

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 0 --accept
    {"commit":6,"global_commit":4,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 0 --accept
    {"commit":7,"global_commit":4,"id":0,"jsonrpc":"2.0","result":true,"term":2}

The user is successfully added once a :term:`quorum` of members have accepted the proposal (``"result":true"``).

Open a network
~~~~~~~~~~~~~~

Once users are added to the opening network, members should decide to make a proposal to open the network:

.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert open_network
    {"commit":4,"global_commit":3,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

Other members are then allowed to vote for the proposal, using the proposal ID returned to the proposer member (here ``1``, as per ``"result":{"completed":false,"id":1}``).

.. code-block:: bash

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 1 --accept
    {"commit":9,"global_commit":8,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 1 --accept
    {"commit":11,"global_commit":10,"id":0,"jsonrpc":"2.0","result":true,"term":2}

Once a quorum of members have approved the network opening (``"result":true``), the network is opened to users (see :ref:`Example App` for a simple business logic and :term:`JSON-RPC` transactions). It is only then that users are able to execute transactions on the business logic defined by the enclave file (``--enclave-file`` option to ``cchost``).

Add new nodes to an open network
--------------------------------

Once the network has been opened by members, it is possible to add new nodes to the network (e.g. to replace a retired node or add a new version of the code). The new node should be started with the ``join`` option:

.. code-block:: bash

    $ cchost --enclave-file /path/to/enclave_library --enclave-type debug
    --node-address node_ip:node_port --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate --quote-file /path/to/quote
    join --network-cert-file /path/to/existing/network_certificate --target-rpc-address target_rpc_ip:target_rpc_port

As opposed to an opening network in which nodes are trusted automatically (see :ref:`Add a new node to an opening network`), new nodes added to an open network should be trusted by a quorum of members before becoming part of the network. When a new node joins an open network, it is assigned a unique node id and is recorded in state `PENDING`. Then, members can vote to accept the new node:

.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert trust_node --node-id new_node_id
    {"commit":13,"global_commit":12,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":2},"term":2}

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 2 --accept
    {"commit":15,"global_commit":14,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 2 --accept
    {"commit":17,"global_commit":16,"id":0,"jsonrpc":"2.0","result":true,"term":2}

Once the proposal successfully completes, the new node automatically becomes part of the network.

Summary diagram
---------------

Once a node is part of the network (started with either the ``start`` or ``join`` option), members are authorised to issue governance transactions and eventually open the network. Only then are users authorised to issue JSON-RPC transactions to CCF.

.. note:: After the network is open to users, members can still issue governance transactions to CCF (for example, adding new users or additional members to the consortium). See :ref:`Governance` for more information about member governance.

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



Node output
-----------

By default node output is written to stdout and to stderr and can be handled accordingly.

There is an option to further generate machine-readable logs for monitoring. To enable this pass `--json-log-path <path_to_file>` when creating a node (in either start or join mode). The generated logs will be in JSON format as displayed below.

.. code-block:: json

        {
            "e_ts": "2019-09-02T14:47:24.589386Z",
            "file": "../src/consensus/raft/raft.h",
            "h_ts": "2019-09-02T14:47:24.589384Z",
            "level": "info",
            "msg": "Deserialising signature at 24\n",
            "number": 651
        }

- `e_ts` is the ISO 8601 UTC timestamp of the log if logged inside the enclave (field will be missing if line was logged on the host side)
- `h_ts` is the ISO 8601 UTC timestamp of the log when logged on the host side
- `file` is the file the log originated from
- `number` is the line number in the file the log originated from
- `level` is the level of the log message [info, debug, trace, fail, fatal]
- `msg` is the log message

.. rubric:: Footnotes

.. [#remote_attestation] When a new node joins an existing network, the network performs the remote attestation protocol by verifying the joining node's quote. It also checks that the version of the code running by the joining node is trusted by the consortium.
