Opening a Network
=================

This sections assumes that a set of nodes has already been started by :term:`operators`. See :ref:`operators/start_network:Starting a New Network`.

Adding Users
------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to :term:`users`. First, :ref:`the identities of trusted users should be generated <users/index:Using CCF Applications>`.

Then, the certificates of trusted users should be registered in CCF via the member governance interface. For example, the first member may decide to make a proposal to add a new user (here, ``user_cert`` is the PEM certificate of the user -- see :ref:`developers/cryptography:Cryptography` for a list of supported algorithms):

.. code-block:: bash

    $ cat add_user.json
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "members/propose",
        "params": {
            "parameter": [<cert of proposed new user>],
            "script": {
                "text": "tables, user_cert = ...; return Calls:call(\"new_user\", user_cert)"
            }
        }
    }

    $ curl https://<ccf-node-address>/members/propose --cacert network_cert --key member0_privk --cert member0_cert --data-binary @add_user.json
    {"commit":21,"global_commit":20,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":0},"term":2}

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member (here ``5``, as per ``"result":{"completed":false,"id":5}``). They may submit an unconditional approval, or their vote may query the current state and proposal. These votes `must` be signed.

.. code-block:: bash

    $ cat vote_accept.json
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "members/vote",
        "params": {
            "ballot": {
                "text": "return true"
            },
            "id": 0
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member1_privk --cert member1_cert --data-binary @vote_accept.json
    {"commit":29,"global_commit":28,"id":0,"jsonrpc":"2.0","result":false,"term":2}

    $ cat vote_conditional.json
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "members/vote",
        "params": {
            "ballot": {
                "text": "tables, calls = ...; return (#calls == 1 and calls[1].func == \"new_user\")"
            },
            "id": 0
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_conditional.json
    {"commit":31,"global_commit":30,"id":0,"jsonrpc":"2.0","result":true,"term":2}

The user is successfully added once a the proposal has received enough votes under the rules of the :term:`constitution` (``"result":true"``).

The user can then make user RPCs, for example ``whoAmI`` to retrieve the unique caller ID assigned to them by CCF:

.. code-block:: bash

    $ cat whoAmI.json
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "users/whoAmI"
    }

    $ curl https://<ccf-node-address>/users/whoAmI --cacert network_cert --key new_user_privk --cert new_user_cert --data-binary @whoAmI.json
    {"commit":34,"global_commit":34,"id":0,"jsonrpc":"2.0","result":{"caller_id":4},"term":2}

For each user CCF also stores arbitrary user-data in a JSON object, which can only be written to by members, subject to the standard proposal-vote governance mechanism. This lets members define initial metadata for certain users; for example to grant specific privileges, associate a human-readable name, or categorise the users. This user-data can then be read (but not written) by user-facing apps.

Registering the Lua Application
-------------------------------

.. note:: This section only applies when deploying Lua applications (i.e. using the ``libluageneric.enclave.so.signed`` enclave library). For C++ applications, this step should be skipped.

.. code-block:: bash

    $ cat set_lua_app.json
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "members/propose",
        "params": {
            "parameter": "<proposed lua app>",
            "script": {
                "text": "tables, app = ...; return Calls:call(\"set_lua_app\", app)"
            }
        }
    }

    $ curl https://<ccf-node-address>/members/propose --cacert network_cert --key member0_privk --cert member0_cert --data-binary @set_lua_app.json
    {"commit":36,"global_commit":35,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":1},"term":2}

Other members are then able to vote for the proposal using the returned proposal id (here ``1``, as per ``"result":{"completed":false,"id":1}``).

The Lua application is successfully registered once the proposal has received enough votes under the rules of the :term:`constitution`.

Opening the Network
-------------------

Once users are added to the opening network, members should decide to make a proposal to open the network:

.. code-block:: bash

    $ cat open_network.json
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "members/propose",
        "params": {
            "script": {
                "text": "return Calls:call(\"open_network\")"
            }
        }
    }

    $ curl https://<ccf-node-address>/members/propose --cacert network_cert --key member0_privk --cert member0_cert --data-binary @open_network.json
    {"commit":15,"global_commit":14,"id":0,"jsonrpc":"2.0","result":{"completed":false,"id":2},"term":2}

Other members are then able to vote for the proposal using the returned proposal id (here ``2``, as per ``"result":{"completed":false,"id":2}``).

Once the proposal has received enough votes under the rules of the :term:`constitution` (``"result":true``), the network is opened to users (see :ref:`developers/example:Example Application` for a simple business logic and transactions). It is only then that users are able to execute transactions on the business logic defined by the enclave file (``--enclave-file`` option to ``cchost``).
