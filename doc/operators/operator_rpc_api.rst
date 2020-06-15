Operator RPC API
================

As well as the following methods, :ref:`users/rpc_api:Common Methods` are also available to operators.

quote
-----

Retrieves quote of single contacted node.

.. literalinclude:: ../schemas/quote_result.json
    :language: json

Example
~~~~~~~

.. code-block:: json

    {
        "quotes": [
            {
                "mrenclave": "9b2a4ca78fc80d76dd29389af6998a4a4b23b0b2571bccaf29c576a569e5bea5",
                "node_id": 0,
                "raw": "0100000002000000e811000000000000030002000000000005000a00939a..."
            }
        ]
    }

quotes
------

Retrieves quotes of all trusted nodes.

.. literalinclude:: ../schemas/quotes_result.json
    :language: json

Example
~~~~~~~

.. code-block:: json

    {
        "quotes": [
            {
                "mrenclave": "9b2a4ca78fc80d76dd29389af6998a4a4b23b0b2571bccaf29c576a569e5bea5",
                "node_id": 0,
                "raw": "0100000002000000e811000000000000030002000000000005000a00939a..."
            },
            {
                "mrenclave": "9b2a4ca78fc80d76dd29389af6998a4a4b23b0b2571bccaf29c576a569e5bea5",
                "node_id": 1,
                "raw": "0100000002000000e811000000000000030002000000000005000a00939a..."
            }
        ]
    }

signed_index
------------

.. literalinclude:: ../schemas/getSignedIndex_result.json
    :language: json

Example
~~~~~~~

.. code-block:: json

    {
        "signed_index": 34,
        "state": "partOfPublicNetwork"
    }
