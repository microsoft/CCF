Example Application
===================

Description
-----------

The repository contains equivalent C++ and a Lua implementations of a simple example application for logging. These are meant to serve as templates for building more useful applications and to showcase core features.

.. note::

    The following description is out-of-date. Logging will be extended to demonstrate more features, and this document should be updated in-sync.

The Logging application implements a trivial protocol, made up of four transaction types:

- ``POST /log/private``, which writes a private log message at a given index. Note that the log message will be encrypted on the ledger and only readable by nodes on the network.

    Log a private message:

    .. code-block:: json

        {
            "id": 42,
            "msg": "A sample private log message"
        }

- ``GET /log/private``, which retrieves a private log message from a given index written by a previous ``POST /log/private`` call.

    Get a private message:

    .. code-block:: json

        {
            "id": 42
        }

- ``POST /log/public``, which writes a public log message at a given index. Note that the log message will be not be encrypted and thus to anyone with access to the ledger.

    Log a public message:

    .. code-block:: json

        {
            "id": 100,
            "msg": "A sample public log message"
        }

- ``GET /log/public``, which retrieves a public public log from a given index written by a previous ``POST /log/public`` call.

    Get a public message:

    .. code-block:: json

        {
            "id": 100
        }


Implementations
---------------

The C++ and Lua implementations of the Logging application are located in the `src/apps <https://github.com/microsoft/CCF/tree/master/src/apps>`_ folder. They are discussed in detail on the following pages:

.. toctree::
   :maxdepth: 2

   logging_cpp
   logging_lua
   logging_rpc_api