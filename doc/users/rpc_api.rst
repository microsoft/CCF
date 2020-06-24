RPC API
=======

The available RPC methods vary depending on your TLS connection identity. Some methods are common to all frontends, others are restricted to the member and node frontends, and the app logic is only exposed to users.

The API can also be retrieved from a running service using the `api`_ and `api/schema`_ methods. For example, using curl:

.. code-block:: bash

    $ curl https://<ccf-node-address>/app/api --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem
    {
      "methods": [
        "api",
        "api/schema",
        "commit",
        "quote",
        "quotes",
        "signed_index",
        "join",
        "metrics",
        "mkSign",
        "network_info",
        "node/ids",
        "primary_info",
        "receipt",
        "receipt/verify",
        "tx",
        "who"
      ]
    }

    $ curl https://<ccf-node-address>/node/api/schema?method="tx" -X GET --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem -H "Content-Type: application/json"
    {
      "params_schema": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "properties": {
          "seqno": {
            "maximum": 9223372036854776000,
            "minimum": -9223372036854776000,
            "type": "integer"
          },
          "view": {
            "maximum": 18446744073709552000,
            "minimum": 0,
            "type": "integer"
          }
        },
        "required": [
          "view",
          "seqno"
        ],
        "title": "tx/params",
        "type": "object"
      },
      "result_schema": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "properties": {
          "status": {
            "enum": [
              "UNKNOWN",
              "PENDING",
              "COMMITTED",
              "INVALID"
            ]
          }
        },
        "required": [
          "status"
        ],
        "title": "tx/result",
        "type": "object"
      }
    }


Common Methods
--------------

commit
~~~~~~

.. literalinclude:: ../schemas/commit_GET_result.json
    :language: json

tx
~~

.. literalinclude:: ../schemas/tx_GET_params.json
    :language: json

.. literalinclude:: ../schemas/tx_GET_result.json
    :language: json

primary_info
~~~~~~~~~~~~

.. literalinclude:: ../schemas/primary_info_GET_result.json
    :language: json

metrics
~~~~~~~

.. literalinclude:: ../schemas/metrics_GET_result.json
    :language: json

api
~~~

.. literalinclude:: ../schemas/api_GET_result.json
    :language: json

api/schema
~~~~~~~~~~

.. literalinclude:: ../schemas/api/schema_GET_params.json
    :language: json
.. literalinclude:: ../schemas/api/schema_GET_result.json
    :language: json

