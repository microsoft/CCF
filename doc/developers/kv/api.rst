Key-Value Store API
===================

This page presents the API that a CCF application must use to read and mutate the replicated key-value store.

A CCF application should define one or multiple public or private :cpp:class:`kv::Map`. Then, each :cpp:class:`ccf::EndpointRegistry::Endpoint` should use the :cpp:class:`kv::Tx` transaction object to read and write to specific :cpp:class:`kv::Map`.

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

.. doxygenclass:: kv::Map
   :project: CCF
   :members: get_name, set_global_hook

Transaction
-----------

.. doxygenclass:: kv::Tx
   :project: CCF
   :members: get_view,

Transaction View
----------------

.. doxygenclass:: kv::Map::TxView
   :project: CCF
   :members: get, put, remove, foreach
