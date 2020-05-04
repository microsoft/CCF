RPC API
=======

The available RPC methods vary depending on your TLS connection identity. Some methods are common to all frontends, others are restricted to the member and node frontends, and the app logic is only exposed to users.

The API can also be retrieved from a running service using the `listMethods`_ and `getSchema`_ methods. For example, using curl:

.. code-block:: bash

    $ curl https://<ccf-node-address>/users/listMethods --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem
    {
      "methods": [
        "LOG_get",
        "LOG_get_pub",
        "LOG_record",
        "LOG_record_anonymous",
        "LOG_record_prefix_cert",
        "LOG_record_pub",
        "getCommit",
        "getMetrics",
        "getNetworkInfo",
        "getPrimaryInfo",
        "getReceipt",
        "getSchema",
        "listMethods",
        "mkSign",
        "verifyReceipt",
        "whoAmI",
        "whoIs"
      ]
    }

    $ curl https://<ccf-node-address>/users/getSchema --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary '{"method": "getPrimaryInfo"}' -H "content-type: application/json"
    {
      "params_schema": {},
      "result_schema": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "properties": {
          "primary_host": {
            "type": "string"
          },
          "primary_id": {
            "maximum": 18446744073709551615,
            "minimum": 0,
            "type": "number"
          },
          "primary_port": {
            "type": "string"
          }
        },
        "required": [
          "primary_id",
          "primary_host",
          "primary_port"
        ],
        "title": "getPrimaryInfo/result",
        "type": "object"
      }
    }


Common Methods
--------------

getCommit
~~~~~~~~~

.. literalinclude:: ../schemas/getCommit_result.json
    :language: json

getPrimaryInfo
~~~~~~~~~~~~~~

.. literalinclude:: ../schemas/getPrimaryInfo_result.json
    :language: json

getMetrics
~~~~~~~~~~

.. literalinclude:: ../schemas/getMetrics_result.json
    :language: json

getSchema
~~~~~~~~~

.. literalinclude:: ../schemas/getSchema_params.json
    :language: json
.. literalinclude:: ../schemas/getSchema_result.json
    :language: json

listMethods
~~~~~~~~~~~

.. literalinclude:: ../schemas/listMethods_result.json
    :language: json
