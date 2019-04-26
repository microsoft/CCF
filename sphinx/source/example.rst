Example App
===========

Description
```````````

The repository contains equivalent C++ and a Lua implementations of a simple example application for logging. These are meant to serve as templates for building more useful applications and to showcase core features. 

.. note::

    The following description is out-of-date. Logging will be extended to demonstrate more features, and this document should be updated in-sync.

The Logging application implements a trivial protocol, made up of two single transaction types:

- ``"LOG_record"``, which writes a log at a given index. Note that the log message will be encrypted on the ledger and only readable by nodes on the network.

    Log a private message:

    .. code-block:: json

        {
            "method": "LOG_record",
            "params": {
                "msg": "A sample private log message"
            }
        }

- ``"LOG_record_pub"``, which writes a log at a given index. Note that the log message will be not be encrypted and thus visible by all users or anyone with access to the ledger.

    Log a public message:

    .. code-block:: json

        {
            "method": "LOG_record_pub",
            "params": {
                "msg": "A sample public log message"
            }
        }

Implementations
```````````````

The C++ and Lua implementations of the Logging application are located in the [CCF]/src/apps folder. They are discussed in detail on the following pages:

.. toctree::
   :maxdepth: 2

   logging_cpp
   logging_lua

Client
``````

There are no particular requirements for the client, other than it should use `JSON-RPC <https://www.jsonrpc.org/specification>`_
over `TLS <https://tools.ietf.org/html/rfc5246>`_. 

If the client is written in C++, subclassing :cpp:class:`::RpcTlsClient` is a good start.