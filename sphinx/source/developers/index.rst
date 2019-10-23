Writing CCF Applications
========================

This section describes how CCF applications can be developed and deployed to a CCF network.

Applications can be written in C++ or Lua (see :ref:`Example App`). An application consists of a collection of endpoints that can be triggered by :term:`users` using JSON-RPC. Each endpoint can define an :ref:`API Schema` to validate user requests.

These endpoints mutate the state of a unique :ref:`Key-Value Store` that represents the internal state of the application. Applications define a set of ``Maps`` (see :ref:`Creating a Map`), mapping from a key to a value. When an application endpoint is triggered, the effects on the Store are committed atomically.

.. warning:: Notifications to be described.

.. toctree::
  :maxdepth: 2
  :caption: Contents:

  example
  demo
  kv/index.rst
  ledger
  cryptography
  performance
  api