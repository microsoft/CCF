Key-Value Serialisation
=======================

Every transaction executed by the primary on its Key-Value store is serialised before being replicated to all backups of the CCF network and written to the ledger. The serialisation format is defined per :cpp:type:`ccf::kv::Map` and distinctly for the key and value types.

.. tip:: Selecting the right serialision format for a KV map depends on the application logic but is generally a trade-off between performance and auditability of the ledger. For example, the default serialisation format for :cpp:type:`ccf::kv::Map` is JSON and allows for easy parsing of transactions in the `public` ledger. For more performance sensitive use cases, apps may define or use their own serialisers.

Serialised byte storage
-----------------------

Serialisers return an owning ``ccf::ByteVector`` for each key and value.
This applies to built-in tables and application-defined maps, including the
backing store for JavaScript maps. Small entries use inline storage; larger
entries grow on the heap. The inline capacity is not a key or value size limit.
Copies own their bytes independently, and growing a byte vector may invalidate
existing pointers and iterators.

``ccf::ByteVector`` is a standalone byte-only container, not an alias of a
third-party vector. It stores up to 16 bytes inline. Native applications must
rebuild against the matching CCF headers when migrating from the previous
SmallVector-based type. Code should use the ``ccf::ByteVector`` byte interface
rather than SmallVector-specific types or base classes.

Ledger serialisation uses a separate, private writer buffer. Its allocation
policy does not change the key/value encoding, ledger format, or transaction
size limits. Exporting the writer's bytes produces an independent copy rather
than consuming its contents.

Custom key and value types
--------------------------

User-defined types can be used for both the key and value types of a :cpp:type:`ccf::kv::Map`. It must be possible to use the key type as the key of an ``std::map`` (so it must be copyable, assignable, and less-comparable), and both types must be serialisable. By default, when using a :cpp:type:`ccf::kv::Map`, serialisation converts to JSON. To add support to your custom types, it should usually be possible to use the ``DECLARE_JSON_...`` macros:

.. literalinclude:: ../../../src/kv/test/kv_serialisation.cpp
    :language: cpp
    :start-after: SNIPPET_START: CustomClass definition
    :end-before: SNIPPET_END: CustomClass definition

Custom serialisers can also be defined. The serialiser itself must be a type implementing ``to_serialised`` and ``from_serialised`` functions for the target type:

.. literalinclude:: ../../../src/kv/test/kv_serialisation.cpp
    :language: cpp
    :start-after: SNIPPET_START: CustomSerialiser definition
    :end-before: SNIPPET_END: CustomSerialiser definition

To use these serialised for a specific map declare the map as a :cpp:class:`ccf::kv::TypedMap`, adding the appropriate serialiser types for the key and value types:

.. literalinclude:: ../../../src/kv/test/kv_serialisation.cpp
    :language: cpp
    :start-after: SNIPPET_START: CustomSerialisedMap definition
    :end-before: SNIPPET_END: CustomSerialisedMap definition

.. note:: Any external tools which wish to parse the ledger will need to know the serialisation format of the tables they care about. It is recommended, though not enforced, that you size-prefix each entry so it can be skipped by tools which do not understand the serialised format.