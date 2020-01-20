Issuing Commands
================

Clients communicate with CCF using framed :term:`JSON-RPC` over :term:`TLS`. The ``method`` must be prefixed with the name of the target frontend (``"users"`` or ``"members"``), separated from the intended ``method`` with a single ``/``.

Users can issue business transactions to CCF using the ``client`` command-line utility built with CCF. For example, to record a message at a specific id with the :ref:`developers/example:Example Application`:

.. code-block:: bash

    $ cat request.json
    {
      "id": 0,
      "method": "users/LOG_record",
      "jsonrpc": "2.0",
      "params":
      {
        "id": 42,
        "msg": "Hello There"
      }
    }

    $ client --pretty-print --rpc-address node_rpc_ip:node_rpc_port --ca networkcert.pem userrpc --req @request.json --cert user_cert.pem --pk user_privk.pem
    Sending RPC to node_rpc_ip:node_rpc_port
    Doing user RPC:
    {
      "commit": 30,
      "global_commit": 29,
      "id": 0,
      "jsonrpc": "2.0",
      "result": true,
      "term": 2
    }

The JSON-RPC response is written to ``stdout`` when the request has been executed:

- ``"id"`` indicates that the response is for request id ``0``
- ``"result": true`` indicates that the request was executed successfully
- ``"commit"`` is the unique version at which the request was executed
- ``"global_commit"`` is the latest version agreed on by the network and forever committed to the ledger, at the time the request was executed
- ``"term"`` indicates the consensus term at which the request was executed

Checking for Commit
-------------------

Because of the decentralised nature of CCF, a request is committed to the ledger only once a number of nodes have agreed on that request.

To guarantee that their request is successfully committed to the ledger, a user needs to issue a ``getCommit`` request, specifying the ``commit`` version received in the JSON-RPC response. If CCF returns a ``global_commit`` greater than the ``commit`` version at which the ``LOG_record`` request was issued `and` that the result ``commit`` is in the same ``term``, then the request was committed to the ledger.

.. code-block:: bash

    $ cat get_commit.json
    {
      "id": 0,
      "method": "users/getCommit",
      "jsonrpc": "2.0",
      "params":
      {
        "commit": 30
      }
   }

    $ client --pretty-print --rpc-address node_rpc_ip:node_rpc_port --ca networkcert.pem userrpc --req @get_commit.json --cert user_cert.pem --pk user_privk.pem
    Sending RPC to node_rpc_ip:node_rpc_port
    Doing user RPC:
    {
      "commit": 31,
      "global_commit": 31,
      "id": 0,
      "jsonrpc": "2.0",
      "result": {
        "commit": 30,
        "term": 2
      },
      "term": 2
    }

In this example, the ``result`` field indicates that the request was executed at ``30`` (``commit``) was in term ``2``, the same term that the ``LOG_record``. Moreover, the ``global_commit`` (``31``) is now greater than the ``commit`` version. The ``LOG_record`` request issued earlier was successfully committed to the ledger.

Transaction receipts
--------------------

Once a transaction has been committed, it is possible to get a receipt for it. That receipt can later be checked against either a CCF service, or offline against the ledger, to prove that the transaction did happen at a particular commit.

To obtain a receipt, a user needs to issue a ``getReceipt`` RPC for a particular commit:

.. code-block:: bash

    $ cat get_receipt.json
    {
      "id": 0,
      "method": "users/getReceipt",
      "jsonrpc": "2.0",
      "params":
      {
        "commit": 30
      }
   }

    $ client --pretty-print --rpc-address node_rpc_ip:node_rpc_port --ca networkcert.pem userrpc --req @get_receipt.json --cert user_cert.pem --pk user_privk.pem
    Sending RPC to node_rpc_ip:node_rpc_port
    Doing user RPC:
    {
      "commit": 31,
      "global_commit": 31,
      "id": 0,
      "jsonrpc": "2.0",
      "result": {
        "receipt": [ ... ],
      },
      "term": 2
    }

Receipts can be verified with the ``verifyReceipt`` RPC:

.. code-block:: bash

    $ cat get_receipt.json
    {
      "id": 0,
      "method": "users/verifyReceipt",
      "jsonrpc": "2.0",
      "params":
      {
        "receipt": [ ... ]
      }
   }

    $ client --pretty-print --rpc-address node_rpc_ip:node_rpc_port --ca networkcert.pem userrpc --req @get_receipt.json --cert user_cert.pem --pk user_privk.pem
    Sending RPC to node_rpc_ip:node_rpc_port
    Doing user RPC:
    {
      "commit": 31,
      "global_commit": 31,
      "id": 0,
      "jsonrpc": "2.0",
      "result": {
        "valid": true,
      },
      "term": 2
    }
