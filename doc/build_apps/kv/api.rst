Key-Value Store API
===================

This page presents the API that a CCF application must use to access and mutate the replicated key-value store.

A CCF application should store its data in one or more :cpp:type:`ccf::kv::Map`. The name, type, and serialisation of these maps is under the application's control. Each invocation of an :cpp:class:`ccf::EndpointRegistry::Endpoint` is given a :cpp:class:`ccf::kv::Tx` transaction object, through which it can read and write to its :cpp:type:`ccf::kv::Map`.

Map
---

.. doxygentypedef:: ccf::kv::Version
   :project: CCF

.. doxygenvariable:: ccf::kv::NoVersion
   :project: CCF

.. doxygenclass:: ccf::kv::TypedMap
   :project: CCF

.. doxygentypedef:: ccf::kv::Map
   :project: CCF

.. doxygenclass:: ccf::kv::TypedValue
   :project: CCF

.. doxygentypedef:: ccf::kv::Value
   :project: CCF

.. doxygenclass:: ccf::kv::TypedSet
   :project: CCF

.. doxygentypedef:: ccf::kv::Set
   :project: CCF

Transaction
-----------

.. doxygenclass:: ccf::kv::ReadOnlyTx
   :project: CCF
   :members: ro

.. doxygenclass:: ccf::kv::Tx
   :project: CCF
   :members: rw, wo

Handles
-------

.. doxygenclass:: ccf::kv::ReadableMapHandle
   :project: CCF
   :members:

.. doxygenclass:: ccf::kv::WriteableMapHandle
   :project: CCF
   :members:

.. doxygenclass:: ccf::kv::MapHandle
   :project: CCF

.. doxygenclass:: ccf::kv::ReadableValueHandle
   :project: CCF
   :members:

.. doxygenclass:: ccf::kv::WriteableValueHandle
   :project: CCF
   :members:

.. doxygenclass:: ccf::kv::ValueHandle
   :project: CCF

.. doxygenclass:: ccf::kv::ReadableSetHandle
   :project: CCF
   :members:

.. doxygenclass:: ccf::kv::WriteableSetHandle
   :project: CCF
   :members:

.. doxygenclass:: ccf::kv::SetHandle
   :project: CCF

Serialisation
-------------

.. doxygenenum:: ccf::kv::EntryType
   :project: CCF