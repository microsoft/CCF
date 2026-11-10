C++ Application
===============

The repository contains a C++ implementation of a simple example application for logging.
These are meant to serve as templates for building more useful applications and to showcase core features.

The C++ implementation of the Logging application is located in the :ccf_repo:`samples/apps/logging/` folder.
It stores log messages, identified by an integer ``id``, in two key-value maps: a private ``records`` map, whose contents are encrypted on the ledger, and a public ``public:records`` map, whose contents are written to the ledger in the clear.

The core of the application is made up of the following endpoints:

- :http:POST:`/app/log/private`, which writes a private log message with a given ``id``.
  The log message is encrypted on the ledger, and is only readable by nodes on the network.

    Log a private message:

    .. code-block:: json

        {
            "id": 42,
            "msg": "A sample private log message"
        }

- :http:GET:`/app/log/private`, which retrieves the private log message with the ``id`` given as a query parameter (for example ``/app/log/private?id=42``), as written by a previous :http:POST:`/app/log/private` call.

    The response contains the message:

    .. code-block:: json

        {
            "msg": "A sample private log message"
        }

- :http:POST:`/app/log/public`, which writes a public log message with a given ``id``.
  The log message is not encrypted, and is readable by anyone with access to the ledger.

    Log a public message:

    .. code-block:: json

        {
            "id": 100,
            "msg": "A sample public log message"
        }

- :http:GET:`/app/log/public`, which retrieves the public log message with the ``id`` given as a query parameter (for example ``/app/log/public?id=100``), as written by a previous :http:POST:`/app/log/public` call.

- :http:DELETE:`/app/log/private` and :http:DELETE:`/app/log/public`, which remove the log message with the ``id`` given as a query parameter.

- :http:GET:`/app/log/private/count` and :http:GET:`/app/log/public/count`, which return the number of messages currently stored in each map.

Most of these endpoints also accept an optional ``scope`` query parameter, which stores and reads messages in a separate map (for example ``records-<scope>``) instead of the default one.

The application also contains further endpoints which demonstrate other CCF features, such as historical queries, receipts, indexing, custom authentication policies, and COSE signed statements.
These are discussed in detail on the following pages, and the full API is listed in :doc:`example_rpc_api`:

.. toctree::
   :maxdepth: 2

   example_cpp
   example_rpc_api
