Opening a Network
=================

This sections assumes that a set of nodes has already been started by :term:`Operators`. See :ref:`operators/start_network:Starting a New Network`.

Adding Users
------------

Once a CCF network is successfully started and an acceptable number of nodes have joined, members should vote to open the network to :term:`Users`. First, :ref:`the identities of trusted users should be generated <users/index:Using Apps>`.

Then, the certificates of trusted users should be registered in CCF via the member governance interface. For example, the first member may decide to make a proposal to add a new user (here, ``user_cert`` is the PEM certificate of the user -- see :ref:`developers/cryptography:Cryptography` for a list of supported algorithms):

.. code-block:: bash

    $ cat add_user.json
    {
        "parameter": [<cert of proposed new user>],
        "script": {
            "text": "tables, user_cert = ...; return Calls:call(\"new_user\", user_cert)"
    }

    $ ./scurl.sh https://<ccf-node-address>/members/propose --cacert network_cert --key member0_privk --cert member0_cert --data-binary @add_user.json -H "content-type: application/json"
    {
        "completed": false,
        "id": 5
    }

Other members are then allowed to vote for the proposal, using the proposal id returned to the proposer member (here ``5``, as per ``"result":{"completed":false,"id":5}``). They may submit an unconditional approval, or their vote may query the current state and proposal. These votes `must` be signed.

.. code-block:: bash

    $ cat vote_accept.json
    {
        "ballot": {
            "text": "return true"
        },
        "id": 5
    }

    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member1_privk --cert member1_cert --data-binary @vote_accept.json -H "content-type: application/json"
    false

    $ cat vote_conditional.json
    {
        "ballot": {
            "text": "tables, calls = ...; return (#calls == 1 and calls[1].func == \"new_user\")"
        },
        "id": 5
    }

    $ ./scurl.sh https://<ccf-node-address>/members/vote --cacert network_cert --key member2_privk --cert member2_cert --data-binary @vote_conditional.json -H "content-type: application/json"
    true

The user is successfully added once a the proposal has received enough votes under the rules of the :term:`Constitution` (indicated by the response body ``true``).

The user can then make user RPCs, for example ``whoAmI`` to retrieve the unique caller ID assigned to them by CCF:

.. code-block:: bash

    $ curl https://<ccf-node-address>/users/whoAmI --cacert network_cert --key new_user_privk --cert new_user_cert
    {
        "caller_id": 4
    }

For each user CCF also stores arbitrary user-data in a JSON object, which can only be written to by members, subject to the standard proposal-vote governance mechanism. This lets members define initial metadata for certain users; for example to grant specific privileges, associate a human-readable name, or categorise the users. This user-data can then be read (but not written) by user-facing apps.

Registering the Lua Application
-------------------------------

.. note:: This section only applies when deploying Lua applications (i.e. using the ``liblua_generic.enclave.so.signed`` enclave library). For C++ applications, this step should be skipped.

.. code-block:: bash

    $ cat set_lua_app.json
    {
        "parameter": "<proposed lua app>",
        "script": {
            "text": "tables, app = ...; return Calls:call(\"set_lua_app\", app)"
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/members/propose --cacert network_cert --key member0_privk --cert member0_cert --data-binary @set_lua_app.json -H "content-type: application/json"
    {
        "completed": false,
        "id": 1
    }

Other members are then able to vote for the proposal using the returned proposal id (here ``1``, as per ``"result":{"completed":false,"id":1}``).

The Lua application is successfully registered once the proposal has received enough votes under the rules of the :term:`Constitution`.

Opening the Network
-------------------

Once users are added to the opening network, members should decide to make a proposal to open the network:

.. code-block:: bash

    $ cat open_network.json
    {
        "script": {
            "text": "return Calls:call(\"open_network\")"
        }
    }

    $ ./scurl.sh https://<ccf-node-address>/members/propose --cacert network_cert --key member0_privk --cert member0_cert --data-binary @open_network.json -H "content-type: application/json"
    {
        "completed": false,
        "id": 2
    }

Other members are then able to vote for the proposal using the returned proposal id (here ``2``, as per ``"result":{"completed":false,"id":2}``).

Once the proposal has received enough votes under the rules of the :term:`Constitution` (``"result":true``), the network is opened to users (see :ref:`developers/example:Example Application` for a simple business logic and transactions). It is only then that users are able to execute transactions on the business logic defined by the enclave file (``--enclave-file`` option to ``cchost``).
