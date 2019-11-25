RPC API
=======

The available RPC methods vary depending on your TLS connection identity. Some methods are common to all frontends, others are restricted to the member and node frontends, and the app logic is only exposed to users.

The API can also be retrieved from a running service using the `listMethods`_ and `getSchema`_ methods. For example, using the CCF client application:

.. code-block:: bash

    $ client --pretty-print --rpc-address 127.99.16.14:36785 --ca networkcert.pem userrpc --req @listMethods.json --cert user1_cert.pem --pk user1_privk.pem
    Doing user RPC:
    {
      "commit": 4,
      "global_commit": 4,
      "id": 1,
      "jsonrpc": "2.0",
      "result": {
        "methods": [
          "LOG_get",
          "LOG_get_pub",
          "LOG_record",
          "LOG_record_pub",
          "getCommit",
          "getPrimaryInfo",
          "getMetrics",
          "getSchema",
          "listMethods",
          "mkSign"
        ]
      },
      "term": 2
    }

    $ client --pretty-print --rpc-address 127.99.16.14:36785 --ca networkcert.pem userrpc --req @getSchema.json --cert user1_cert.pem --pk user1_privk.pem
    Doing user RPC:
    {
      "commit": 4,
      "global_commit": 4,
      "id": 1,
      "jsonrpc": "2.0",
      "result": {
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
      },
      "term": 2
    }


Common Methods
--------------

getCommit
~~~~~~~~~

.. jsonschema:: ../schemas/getCommit_params.json
.. jsonschema:: ../schemas/getCommit_result.json

getPrimaryInfo
~~~~~~~~~~~~~~

.. jsonschema:: ../schemas/getPrimaryInfo_result.json

getMetrics
~~~~~~~~~~

.. jsonschema:: ../schemas/getMetrics_result.json

getSchema
~~~~~~~~~

.. jsonschema:: ../schemas/getSchema_params.json
.. jsonschema:: ../schemas/getSchema_result.json

listMethods
~~~~~~~~~~~

.. jsonschema:: ../schemas/listMethods_result.json
