Opening a Network
=================

This sections assumes that a set of nodes has already been started by :term:`operators`. See :ref:`operators/start_network:Starting a New Network`.

Adding Users
------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to :term:`users`. First, :ref:`the identities of trusted users should be generated <users/index:Using CCF Applications>`.

Then, the certificates of trusted users should be registered in CCF via the member governance interface. For example, the first member may decide to make a proposal to add a new user (here, ``user_cert`` is the PEM certificate of the user -- see :ref:`developers/cryptography:Cryptography` for a list of supported algorithms):

.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert add_user --user-cert user_cert
    {"commit":4,"global_commit":3,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":0},"term":2}

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member (here ``0``, as per ``"result":{"completed":false,"id":0}``).

.. code-block:: bash

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 0 --accept
    {"commit":6,"global_commit":4,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 0 --accept
    {"commit":7,"global_commit":4,"id":0,"jsonrpc":"2.0","result":true,"term":2}

The user is successfully added once a :term:`quorum` of members have accepted the proposal (``"result":true"``).

The user can then make RPCs, for example ``whoAmI`` to retrieve the unique caller ID assigned to them by CCF:

.. code-block:: bash

    ./client --rpc-address rpc_ip:rpc_port --ca network_cert --cert new_user_cert --pk new_user_privk --req '{"jsonrpc": "2.0", "id": 0, "method": "users/whoAmI"}'
    {"commit":26,"global_commit":26,"id":0,"jsonrpc":"2.0","result":{"caller_id":3},"term":2}

For each user CCF also stores arbitrary user-data in a JSON object, which can only be written to by members, subject to the standard proposal-vote governance mechanism. This lets members define initial metadata for certain users; for example to grant specific privileges, associate a human-readable name, or categorise the users. This user-data can then be read (but not written) by user-facing apps.

Registering the Lua Application
-------------------------------

.. note:: This section only applies when deploying Lua applications (i.e. using the ``libluageneric.enclave.so.signed`` enclave library). For C++ applications, this step should be skipped.



.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert set_lua_app --lua-app-file /path/to/lua/app_script
    {"commit":9,"global_commit":8,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member (here ``1``, as per ``"result":{"completed":false,"id":1}``).

.. code-block:: bash

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 1 --accept
    {"commit":11,"global_commit":10,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 1 --accept
    {"commit":13,"global_commit":12,"id":0,"jsonrpc":"2.0","result":{"completed":true,"id":1},"term":2}

The Lua application is successfully registered once a :term:`quorum` of members have accepted the proposal (``"result":true"``).

Opening the Network
-------------------

Once users are added to the opening network, members should decide to make a proposal to open the network:

.. code-block:: bash

    $ memberclient --cert member1_cert --privk member1_privk --rpc-address rpc_ip:rpc_port --ca network_cert open_network
    {"commit":15,"global_commit":14,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":2},"term":2}

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member (here ``2``, as per ``"result":{"completed":false,"id":2}``).

.. code-block:: bash

    $ memberclient --cert member2_cert --privk member2_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 2 --accept
    {"commit":17,"global_commit":16,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ memberclient --cert member3_cert --privk member3_privk --rpc-address rpc_ip:rpc_port --ca network_cert vote --proposal-id 2 --accept
    {"commit":19,"global_commit":18,"id":0,"jsonrpc":"2.0","result":true,"term":2}

Once a quorum of members have approved the network opening (``"result":true``), the network is opened to users (see :ref:`developers/example:Example Application` for a simple business logic and :term:`JSON-RPC` transactions). It is only then that users are able to execute transactions on the business logic defined by the enclave file (``--enclave-file`` option to ``cchost``).
