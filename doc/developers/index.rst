Building Apps
=============

This section describes how CCF applications can be developed and deployed to a CCF network.

Applications can be written in C++ or Lua (see :ref:`developers/example:Example Application`). An application consists of a collection of endpoints that can be triggered by :term:`Users`. Each endpoint can define an :ref:`developers/logging_cpp:API Schema` to validate user requests.

These endpoints mutate the state of a unique :ref:`developers/kv/index:Key-Value Store` that represents the internal state of the application. Applications define a set of ``Maps`` (see :ref:`developers/kv/kv_how_to:Creating a Map`), mapping from a key to a value. When an application endpoint is triggered, the effects on the Store are committed atomically.

.. warning:: Notifications to be described.

.. toctree::
  :maxdepth: 2
  :caption: Contents:

  example
  build_app
  demo
  kv/index.rst
  ledger
  consensus
  cryptography
  threading
  performance
  api