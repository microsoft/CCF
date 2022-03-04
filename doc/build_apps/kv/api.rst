Key-Value Store API
===================

This page presents the API that a CCF application must use to access and mutate the replicated key-value store.

A CCF application should store its data in one or more :cpp:type:`kv::Map`. The name, type, and serialisation of these maps is under the application's control. Each invocation of an :cpp:class:`ccf::EndpointRegistry::Endpoint` is given a :cpp:class:`kv::Tx` transaction object, through which it can read and write to its :cpp:type:`kv::Map`.

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

.. doxygenclass:: kv::TypedValue
   :project: CCF

.. doxygentypedef:: kv::Value
   :project: CCF

.. doxygenclass:: kv::TypedSet
   :project: CCF

.. doxygentypedef:: kv::Set
   :project: CCF

Transaction
-----------

.. doxygenclass:: kv::ReadOnlyTx
   :project: CCF
   :members: ro

.. doxygenclass:: kv::Tx
   :project: CCF
   :members: rw, wo

Handles
-------

.. doxygenclass:: kv::ReadableMapHandle
   :project: CCF
   :members:

.. doxygenclass:: kv::WriteableMapHandle
   :project: CCF
   :members:

.. doxygenclass:: kv::MapHandle
   :project: CCF

.. doxygenclass:: kv::ReadableValueHandle
   :project: CCF
   :members:

.. doxygenclass:: kv::WriteableValueHandle
   :project: CCF
   :members:

.. doxygenclass:: kv::ValueHandle
   :project: CCF

.. doxygenclass:: kv::ReadableSetHandle
   :project: CCF
   :members:

.. doxygenclass:: kv::WriteableSetHandle
   :project: CCF
   :members:

.. doxygenclass:: kv::SetHandle
   :project: CCF

Serialisation
-------------

.. doxygenenum:: kv::EntryType
   :project: CCF