Key-Value Store API
===================

This page presents the API that a CCF application must use to access and mutate the replicated key-value store.

A CCF application should store its data in one or more :cpp:type:`kv::Map`. The name, type, and serialisation of these maps is under the application's control. Each invocation of an :cpp:class:`ccf::EndpointRegistry::Endpoint` is given a :cpp:class:`kv::Tx` transaction object, through which it can read and write to its :cpp:type:`kv::Map`.

Store
-----

.. doxygenclass:: kv::Store
   :project: CCF
   :members: create, get

Map
---

.. doxygentypedef:: kv::Version
   :project: CCF

.. doxygenvariable:: kv::NoVersion
   :project: CCF

.. doxygenclass:: kv::TypedMap
   :project: CCF

.. doxygentypedef:: kv::Map
   :project: CCF

Transaction
-----------

.. doxygenclass:: kv::ReadOnlyTx
   :project: CCF
   :members: ro

.. doxygenclass:: kv::Tx
   :project: CCF
   :members: rw, ro, wo

Handle
------

.. doxygenclass:: kv::ReadableMapHandle
   :project: CCF
   :members: get, has, foreach, get_version_of_previous_write

.. doxygenclass:: kv::WriteableMapHandle
   :project: CCF
   :members: put, remove

.. doxygenclass:: kv::MapHandle
   :project: CCF
