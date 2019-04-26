KV Serialisation
================

Every transaction executed by the leader on its key-value store is serialised before being replicated to all followers of the CCF network and written to the ledger.

Transactions on private :cpp:class:`kv::Map` are encrypted before being serialised while transactions on public :cpp:class:`kv::Map` are only integrity-protected and readable by anyone with access to the ledger.

.. note:: Transactions are serialised using MessagePack_ and to which is prepended a header for integrity protection.

.. _protocol:

Serialised format
-----------------

The following table describes the structure of a serialised KV store transaction.

+----------+------------------------------------------+-------------------------------------------------------------------------+
|          | Field Name                               | Description                                                             |
+==========+==========================================+=========================================================================+
|          | AES GCM Header                           | IV and tag fields required to decrypt and verify integrity              |
+ Header   +------------------------------------------+-------------------------------------------------------------------------+
|          | Public Length                            | Length of serialised public domain                                      |
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
| | Public |     |   | | K                            | | Key                                                                   |
| | Domain |     |   | | Ver                          | | Version                                                               |
+          +-----+---+--------------------------------+-------------------------------------------------------------------------+
|          |     | uint64_t                           | | Write count                                                           |
+          |     +------------------------------------+-------------------------------------------------------------------------+
|          |     | **Repeating [0..write count]**                                                                               |
+          |     +---+--------------------------------+-------------------------------------------------------------------------+
|          |     |   | | K                            | | Key                                                                   |
|          |     |   | | V                            | | Value                                                                 |
+          +-----+---+--------------------------------+-------------------------------------------------------------------------+
|          |     | | uint64_t                         | | Remove count                                                          |
+          +     +------------------------------------+-------------------------------------------------------------------------+
|          |     | **Repeating [0..remove count]**                                                                              |
+          +     +---+--------------------------------+-------------------------------------------------------------------------+
|          |     |   | | K                            | | Key                                                                   |
+----------+-----+---+--------------------------------+-------------------------------------------------------------------------+
| | Private| **Optional**                                                                                                       |
| | Domain | | Encrypted serialised private domain blob.                                                                        |
+----------+--------------------------------------------------------------------------------------------------------------------+

.. _MessagePack: https://github.com/msgpack/msgpack-c
