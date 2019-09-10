Starting up a network
=====================

Creating a new network
~~~~~~~~~~~~~~~~~~~~~~

To start up a network, the first node of the network should be started with the ``start`` option:

.. code-block:: bash

    $ cchost --enclave-file /path/to/enclave_library --enclave-type debug
    --node-address node_ip:node_port --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate --quote-file /path/to/quote
    start --network-cert-file /path/to/network_certificate --gov-script /path/to/lua/governance_script
    --member-certs member_certificates_glob --user-certs user_certificates_glob

When starting up, the node generates its own key pair and outputs the certificate associated with its public key at the location specified by ``--node-cert-file``. A quote file, required for remote attestation, is also output at the location specified by ``--quote-file``. The certificate of the freshly-created CCF network is also output at the location specified by ``--network-cert-file``.

.. note:: The network certificate should be used by users and members as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network. For the ``client`` and ``memberclient`` utilities, ``--ca /path/to/network_certificate`` should always be specified.

The :ref:`governance` rules are defined as a Lua script passed via the ``--gov-script`` option. For example, a default set of `governance rules <https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov.lua>`_ can be used to define a majority of members as the :term:`quorum` of the consortium.

The identities of members and users are specified as `glob patterns <https://en.wikipedia.org/wiki/Glob_(programming)>`_ via the ``--member-certs`` and ``--user-certs`` option, respectively. For example, if 2 members (``member1_cert.pem`` and ``member2_cert.pem``) and 3 users (``user1_cert.pem``, ``user2_cert.pem`` and ``user3_cert.pem``) should be added to CCF, operators should specify ``--member-certs member*_cert.pem`` and ``--user-certs user*_cert.pem``.

.. note:: Once a CCF network is started, members can add other members and users via governance. See :ref:`Submitting a new proposal` for more information.

When CCF is used to run a custom Lua application, the starting node should also be started with the ``--app-script /path/to/lua/application_script`` (see the `samples folder <https://github.com/microsoft/CCF/tree/master/samples/apps>`_ for example of Lua applications).

Joining an existing network
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To join an existing network, other nodes should be started with the ``join`` option:

.. code-block:: bash

     $ cchost --enclave-file /path/to/enclave_library --enclave-type debug
    --node-address node_ip:node_port --rpc-address rpc_ip:rpc_port
    --public-rpc-address public_rpc_ip:public_rpc_port --ledger-file /path/to/ledger
    --node-cert-file /path/to/node_certificate --quote-file /path/to/quote
    join --network-cert-file /path/to/existing/network_certificate --target-rpc-address target_rpc_ip:target_rpc_port

The node takes the certificate of the existing network to join via ``--network-cert-file`` and initiates an enclave-to-enclave TLS connection to an existing node of the network as specified by ``--target-rpc-address``. Once the join protocol [#remote_attestation]_ completes, the joining node becomes part of the network as a backup (see :ref:`Ledger replication` for more details on consensus protocols).

.. note:: When starting up the network or when joining an existing network, the network secrets required to decrypt the ledger are sealed and written to a file so that the network can later be recovered. See :ref:`Catastrophic Recovery` for more details on how to recover a crashed network.

Summary diagram
~~~~~~~~~~~~~~~

Once a node is part of the network (started with either the ``start`` or ``join`` option), members and users are authorised to issue JSON-RPC transactions to CCF.

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

        loop Governance transactions
            Members->>+Node 0: JSON-RPC Request
            Node 0-->>Members: JSON-RPC Response
            Members->>+Node 1: JSON-RPC Request
            Node 1-->>Members: JSON-RPC Response
        end

        loop Business transactions
            Users->>+Node 0: JSON-RPC Request
            Node 0-->>Users: JSON-RPC Response
            Users->>+Node 1: JSON-RPC Request
            Node 1-->>Users: JSON-RPC Response
        end


Updating enclave code
~~~~~~~~~~~~~~~~~~~~~

For new nodes to be able to join the network, the version of the code they run (as specified by the ``--enclave-file``) should be first trusted by the consortium of members.

If the version of the code being executed needs to be updated (for example, to support additional JSON-RPC endpoints), members can create a ``new_code`` proposal, specifying the new code version (e.g. ``3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9``):

.. code-block:: bash

    memberclient --cert member_cert --privk member_privk --rpc-address node_ip:node_port --ca network_cert add_code --new-code-id code_version

Once the proposal has been accepted, nodes running the new code are authorised join the network. This allows stopping nodes running older versions of the code.

.. note:: It is important to keep the code compatible with the previous version, since there will be a point in time in which the new code is running on at least one node, while the other version is running on a different node.

.. note:: The safest way to restart or replace nodes is by stopping a single node running the old version and starting a node running the new version as a sequence of operations, in order to avoid a situation in which most nodes have been stopped, and new nodes will not be able to join since it would be impossible to reach a majority of nodes agreeing to accept new nodes (this restriction is imposed by the consensus algorithm).


Node output
~~~~~~~~~~~

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
