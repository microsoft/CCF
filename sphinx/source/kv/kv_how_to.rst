Key-Value store How-To
======================

The key-value :cpp:class:`kv::Store` is a collection of :cpp:class:`kv::Maps` that is available from all the end-points of an application. There is one unique ``Store`` created in the enclave of each node that is passed to the constructor of all applications.

.. code-block:: cpp

    Store tables;

Creating a Map
--------------

A :cpp:class:`kv::Map` (often referred to as a ``Table``) is created in the constructor of an application.

When a ``Map`` is created, its name and the types of the key and value mapping should be specified.

A ``Map`` can either be created as private (default) or public. Transactions on private maps are written to the ledger in encrypted form and can only be decrypted in the enclave of the nodes that have joined the network. Transactions on public maps are written to the ledger as plaintext and can be read from outside the enclave. The security domain of a map (public or private) cannot be changed after its creation.

.. code-block:: cpp

    using namespace std;
    // Private map. Mapping: string -> string
    auto& map_priv = tables.create<string, string>("map1");

    // Public map. Mapping: string -> string
    auto& map_pub = tables.create<string, string>("map2", kv::SecurityDomain::PUBLIC);

    // Private map. Mapping: uint64_t -> string
    auto& map_priv_int = tables.create<uint64_t, string>("map3", kv::SecurityDomain::PRIVATE);


Creating a ``Transaction``
--------------------------

A :cpp:class:`kv::Tx` corresponds to the atomic operations that can be executed on the key-value ``Store``. They can affect one or multiple ``Map`` and should be committed for their action to take effect.

A single ``Transaction`` is passed to all the end-points of an application and should be used to interact with the key-value ``Store``. When the end-point successfully completes, the node on which the end-point was triggered tries to commit the Transaction to apply the changes to the Store.

For each ``Map`` that a Transaction wants to write to or read from, a :cpp:class:`kv::Map::TxView` should first be acquired.

.. code-block:: cpp

    Store::Tx tx;
    // View on map_priv
    auto view_map1 = tx.get_view(map_priv);

    // Two Views created at the same time on map_pub and map_priv_int, respectively
    auto [view_map2, view_map3] = tx.get_view(map_pub, map_priv_int);


Modifying a ``View``
--------------------

Once a ``View`` on a specific ``Map`` has been obtained, it is possible to:

- write (:cpp:class:`kv::Map::TxView::put`) a new value for a key
- read (:cpp:class:`kv::Map::TxView::get`) the value associated with a key
- delete (:cpp:class:`kv::Map::TxView::remove`) a key-value pair.

.. code-block:: cpp

    // Writing to a View over map_priv
    view_map1->put("key1", "value1");

    // Reading from that View
    auto v1 = view_map1->get("key1"); // v1.value() == "value1"

    // Removing the only key-pair in that View
    view_map1->remove("key1");

    // View is now empty
    view_map1->get("key1"); // v1.has_value() == false

Committing a ``Transaction``
----------------------------

Once changes on one or multiple ``View`` need to be recorded, the ``Transaction`` associated with the ``View`` should be committed.
Once committed, the changes applied to the ``View`` are recorded in the ``Map`` such that new ``Transaction`` will be able to access these changes.

.. code-block:: cpp

    Store::Tx tx;
    auto view_map1 = tx.get_view(map_priv);
    view_map1->put("key1", "value1");

    // Committing changes
    auto rc = tx.commit(); // If successful, rc = kv::CommitSuccess::OK

    // New Transaction
    Store::Tx tx_new;
    auto view_map1_new = tx_new.get_view(map_priv);
    auto v1 = view_map1_new->get("key1"); // v1.value() == "value1"

When a ``Transaction`` is committed, the :cpp:type:`kv::Version` (index) of the ``Store`` is incremented.

.. note:: In a CCF network, a ``Transaction`` (delta) is serialised, replicated and written to the ledger every time it is successfully committed.

Removing a key
--------------

If a key-value pair was written to a ``Map`` by a previous ``Transaction``, it is possible to delete this key. Because of the append-only nature of the ``Store``, this key-value pair is not actually removed from the ``Map`` but instead explicitly marked as deleted from the version that the corresponding ``Transaction`` is committed at.

.. code-block:: cpp

    // Assuming that "key1" has already been committed
    Store::Tx tx;
    auto view_map1 = tx.get_view(map_priv);
    auto v = view_map1->get("key1"); // v.value() == "value1"
    view_map1->remove("key1");
    auto rc = tx.commit();

    // New Transaction
    Store::Tx tx_new;
    auto view_map1_new = tx.get_view(map_priv);
    auto v1 = view_map1_new->get("key1"); // v1.has_value() == false

Global commit
-------------

A ``Map`` is globally committed at a specific :cpp:type:`kv::Version` when it is not possible to access the state of that ``Map`` prior to that version.
This is useful when it is certain that the state of the ``Store`` prior to a specific version will never need to be read or modified.

The :cpp:class:`kv::Map::TxView::get_globally_committed` member function returns the value of a key that we know has been globally committed.

.. note:: In a CCF network, a ``Transaction`` (delta) is globally committed when a majority of the nodes have successfully applied that ``Transaction`` to their ``Store``. As such, the CCF framework is in charge of committing transactions globally and applications are not allowed to commit transactions globally.

.. code-block:: cpp

    // Assuming that "key1":"value1" has already been committed
    Store::Tx tx;
    auto view_map1 = tx.get_view(map_priv);

    // "key1" has not yet been globally committed
    auto v = view_map1.get_globally_committed("key1"); // v.has_value() == 0

    // Meanwhile, the CCF network globally commits the transaction in which "key1" was written
    auto v1 = view_map1.get_globally_committed("key1"); // v1.has_value() == "value1"

----------

Miscellaneous
-------------

Custom key and value types
~~~~~~~~~~~~~~~~~~~~~~~~~~

User-defined types can also be used for the types of the key and value mapping of each :cpp:class:`kv::Map`. When defining each custom type, the following conditions must be met:

- For both the custom key and value types, the ``MSGPACK_DEFINE();`` macro should be used to declare each members of the custom type for serialisation.
- For the custom key type, the ``==`` operator should be defined.

.. code-block:: cpp

    struct CustomKey
    {
        uint64_t id;
        std::string name;

        bool operator==(const CustomKey& other) const
        {
            return id == other.id && name == other.name;
        }

        MSGPACK_DEFINE(id, name);
    };

    struct CustomValue
    {
        uint64_t value;
        std::string name;

        MSGPACK_DEFINE(value, name);
    };

    auto& map = tables.create<CustomKey, CustomValue>("map");

``foreach()``
~~~~~~~~~~~~~

Key-value pairs can only be retrieved (:cpp:class:`kv::Map::TxView::get`) from a key. However, it is sometimes necessary to access the key for a given value.

A ``View`` offers a :cpp:class:`kv::Map::TxView::foreach` member function to iterate over all the elements written to that ``Map`` so far and run a lambda function for each key-value pair.

.. code-block:: cpp

    using namespace std;
    // Assuming that "key1":"value1" and "key2":"value2" have already been committed
    Store::Tx tx;
    auto view_map1 = tx.get_view(map_priv);

    // Outputs:
    //  key: key1 - value: value1
    //  key: key2 - value: value2
    view_map1->foreach([](string& key, string& value) {
        cout << " key: " << key << " - value: " << value << endl;
    });
