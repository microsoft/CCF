KV Serialisation
================

Every transaction executed by the primary on its key-value store is serialised before being replicated to all backups of the CCF network and written to the ledger.

Writes to private :cpp:class:`kv::Map`\s are encrypted before being written to the ledger, and can only be decrypted by other nodes within the service. Writes to public :cpp:class:`kv::Map`\s are only integrity-protected; they are readable by anyone with access to the ledger.

.. note:: Transactions are serialised to MessagePack_ with a prepended header for integrity protection.

Serialised Transaction Format
-----------------------------

The ledger is stored as a series of a 4 byte transaction length field followed by a transaction.

The following table describes the structure of a serialised KV Store transaction.

+----------+------------------------------------------+-------------------------------------------------------------------------+
|          | Field Type                               | Description                                                             |
+==========+==========================================+=========================================================================+
|          | AES GCM Header                           | IV and tag fields required to decrypt and verify integrity              |
+ Header   +------------------------------------------+-------------------------------------------------------------------------+
|          | uint64_t                                 | Length of serialised public domain                                      |
+----------+------------------------------------------+-------------------------------------------------------------------------+
|          | :cpp:type:`kv::Version`                  | Transaction version                                                     |
+          +------------------------------------------+-------------------------------------------------------------------------+
|          | **Repeating [0..n]**                     | With ``n`` the number of maps in the transaction                        |
+          +-----+------------------------------------+-------------------------------------------------------------------------+
|          |     | | ``KOT_MAP_START_INDICATOR``      | | Indicates the start of a new serialised :cpp:class:`kv::Map`          |
|          |     | | char[]                           | | Name of the serialised :cpp:class:`kv::Map`                           |
|          +-----+------------------------------------+-------------------------------------------------------------------------+
|          |     | | :cpp:type:`kv::Version`          | | Read version                                                          |
|          +-----+------------------------------------+-------------------------------------------------------------------------+
|          |     | uint64_t                           | | Read count                                                            |
|          |     +------------------------------------+-------------------------------------------------------------------------+
|          |     | **Repeating [0..read count]**                                                                                |
+          |     +---+--------------------------------+-------------------------------------------------------------------------+
| | Public |     |   | | uint64_t                     | | Key length                                                            |
| | Domain |     |   | | K                            | | Key                                                                   |
|          |     |   | | Ver                          | | Version                                                               |
+          +-----+---+--------------------------------+-------------------------------------------------------------------------+
|          |     | uint64_t                           | | Write count                                                           |
+          |     +------------------------------------+-------------------------------------------------------------------------+
|          |     | **Repeating [0..write count]**                                                                               |
+          |     +---+--------------------------------+-------------------------------------------------------------------------+
|          |     |   | | uint64_t                     | | Key length                                                            |
|          |     |   | | K                            | | Key                                                                   |
|          |     |   | | uint64_t                     | | Value length                                                          |
|          |     |   | | V                            | | Value                                                                 |
+          +-----+---+--------------------------------+-------------------------------------------------------------------------+
|          |     | | uint64_t                         | | Remove count                                                          |
+          +     +------------------------------------+-------------------------------------------------------------------------+
|          |     | **Repeating [0..remove count]**                                                                              |
+          +     +---+--------------------------------+-------------------------------------------------------------------------+
|          |     |   | | uint64_t                     | | Key length                                                            |
|          |     |   | | K                            | | Key                                                                   |
+----------+-----+---+--------------------------------+-------------------------------------------------------------------------+
| | Private| **Optional**                                                                                                       |
| | Domain | | Encrypted serialised private domain blob.                                                                        |
+----------+--------------------------------------------------------------------------------------------------------------------+

Custom key and value types
--------------------------

User-defined types can be used for both the key and value types of a :cpp:class:`kv::Map`. It must be possible to use the key type as the key of an ``std::map`` (so it must be copyable, assignable, and less-comparable), and both types must be serialisable. By default, when using a :cpp:class:`kv::Map`, serialisation converts to `MessagePack`_ using `msgpack-c`_. To add support to your custom types, it should usually be possible to use the ``MSGPACK_DEFINE`` macro:

.. literalinclude:: ../../../src/kv/test/kv_serialisation.cpp
    :language: cpp
    :start-after: SNIPPET_START: CustomClass definition
    :end-before: SNIPPET_END: CustomClass definition

Custom serialisers can also be defined. The serialiser itself must be a type implementing ``to_serialised`` and ``from_serialised`` functions for the target type:

.. literalinclude:: ../../../src/kv/test/kv_serialisation.cpp
    :language: cpp
    :start-after: SNIPPET_START: CustomSerialiser definition
    :end-before: SNIPPET_END: CustomSerialiser definition

To use these serialised for a specific map declare the map as a :cpp:class:`kv::TypedMap`, adding the appropriate serialiser types for the key and value types:

.. literalinclude:: ../../../src/kv/test/kv_serialisation.cpp
    :language: cpp
    :start-after: SNIPPET_START: CustomSerialisedMap definition
    :end-before: SNIPPET_END: CustomSerialisedMap definition

.. note:: Any external tools which wish to parse the ledger will need to know the serialisation format of the tables they care about. It is recommended, though not enforced, that you size-prefix each entry so it can be skipped by tools which do not understand the serialised format.

.. _MessagePack: https://msgpack.org/
.. _msgpack-c: https://github.com/msgpack/msgpack-c