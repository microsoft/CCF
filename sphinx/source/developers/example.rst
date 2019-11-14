Example Application
===================

Description
-----------

The repository contains equivalent C++ and a Lua implementations of a simple example application for logging. These are meant to serve as templates for building more useful applications and to showcase core features.

.. note::

    The following description is out-of-date. Logging will be extended to demonstrate more features, and this document should be updated in-sync.

The Logging application implements a trivial protocol, made up of four transaction types:

- ``"LOG_record"``, which writes a log at a given index. Note that the log message will be encrypted on the ledger and only readable by nodes on the network.

    Log a private message:

    .. code-block:: json

        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "users/LOG_record",
            "params": {
                "id": 42,
                "msg": "A sample private log message"
            }
        }

- ``"LOG_get"``, which retrieves a log from a given index written by a previous ``"LOG_record"`` call.

    Get a private message:

    .. code-block:: json

        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "users/LOG_get",
            "params": {
                "id": 42
            }
        }

- ``"LOG_record_pub"``, which writes a log at a given index. Note that the log message will be not be encrypted and thus to anyone with access to the ledger.

    Log a public message:

    .. code-block:: json

        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "users/LOG_record_pub",
            "params": {
                "id": 100,
                "msg": "A sample public log message"
            }
        }

- ``"LOG_get_pub"``, which retrieves a public log from a given index written by a previous ``"LOG_record_pub"`` call.

    Get a public message:

    .. code-block:: json

        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "users/LOG_get_pub",
            "params": {
                "id": 100
            }
        }


Implementations
---------------

The C++ and Lua implementations of the Logging application are located in the `src/apps <https://github.com/microsoft/CCF/tree/master/src/apps>`_ folder. They are discussed in detail on the following pages:

.. toctree::
   :maxdepth: 2

   logging_cpp
   logging_lua
   logging_rpc_api