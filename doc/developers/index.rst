Build Apps
==========

This section describes how CCF applications can be developed and deployed to a CCF network.

Applications can be written in JavaScript or C++. An application consists of a collection of endpoints that can be triggered by :term:`Users`. Each endpoint can define an :ref:`developers/logging_cpp:API Schema` to validate user requests.

These endpoints can read or mutate the state of a unique :ref:`developers/kv/index:Key-Value Store` that represents the internal state of the application. Applications define a set of ``Maps`` (see :ref:`developers/kv/kv_how_to:Creating a Map`), mapping from a key to a value. When an application endpoint is triggered, the effects on the Store are committed atomically.

.. toctree::
  :maxdepth: 2
  :caption: Contents:

  example
  js_app
  build_app
  run_app
  demo
  auth/index.rst
  kv/index.rst
  upgrading_app
  api