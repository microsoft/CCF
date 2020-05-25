Key-Value Store How-To
======================

The Key-Value :cpp:class:`kv::Store` is a collection of :cpp:class:`kv::Maps` that are available from all the end-points of an application. There is one unique ``Store`` created in the enclave of each node that is passed to the constructor of all applications.

.. code-block:: cpp

    Store tables;

Creating a Map
--------------

A :cpp:class:`kv::Map` (often referred to as a ``Table``) is created in the constructor of an application. It maps a unique ``key`` to a ``value``.

When a ``Map`` is created, its name and the types of the key and value mapping should be specified.

A ``Map`` can either be created as private (default) or public. Transactions on private maps are written to the ledger in encrypted form and can only be decrypted in the enclave of the nodes that have joined the network. Transactions on public maps are written to the ledger as plaintext and can be read from outside the enclave (only their integrity is protected). The security domain of a map (public or private) cannot be changed after its creation.

.. code-block:: cpp

    using namespace std;
    // Private map. Mapping: string -> string
    auto& map_priv = tables.create<string, string>("map1");

    // Public map. Mapping: string -> string
    auto& map_pub = tables.create<string, string>("map2", kv::SecurityDomain::PUBLIC);

    // Private map. Mapping: uint64_t -> string
    auto& map_priv_int = tables.create<uint64_t, string>("map3", kv::SecurityDomain::PRIVATE);


Accessing the ``Transaction``
-----------------------------

A :cpp:class:`kv::Tx` corresponds to the atomic operations that can be executed on the Key-Value ``Store``. A transaction can affect one or multiple ``Map`` and are automatically committed by CCF once a RPC handler returns.

A single ``Transaction`` (``tx``) is passed to all the end-points of an application and should be used to interact with the Key-Value ``Store``.

When the end-point successfully completes, the node on which the end-point was triggered attempts to commit the transaction to apply the changes to the Store. Once the transaction is committed successfully, it is automatically replicated by CCF and should globally commit.

For each ``Map`` that a Transaction wants to write to or read from, a :cpp:class:`kv::Map::TxView` should first be acquired.

.. code-block:: cpp

    // View on map_priv
    auto view_map1 = tx.get_view(map_priv);

    // Two Views created at the same time on map_pub and map_priv_int, respectively
    auto [view_map2, view_map3] = tx.get_view(map_pub, map_priv_int);


Modifying a ``View``
--------------------

Once a ``View`` on a specific ``Map`` has been obtained, it is possible to:

- write (:cpp:class:`kv::Map::TxView::put`) a new value for a key;
- read (:cpp:class:`kv::Map::TxView::get`) the value associated with a key;
- delete (:cpp:class:`kv::Map::TxView::remove`) a Key-Value pair.

.. code-block:: cpp

    // Writing to a View over map_priv
    view_map1->put("key1", "value1");

    // Reading from that View
    auto v1 = view_map1->get("key1");
    assert(v1.value() == "value1");

    // Removing the only key-pair in that View
    view_map1->remove("key1");

    // View is now empty
    view_map1->get("key1");
    assert(v1.has_value() == false);

Removing a key
--------------

If a Key-Value pair was written to a ``Map`` by a previous ``Transaction``, it is possible to delete this key. Because of the append-only nature of the ``Store``, this Key-Value pair is not actually removed from the ``Map`` but instead explicitly marked as deleted from the version that the corresponding ``Transaction`` is committed at.

.. code-block:: cpp

    // Assuming that "key1" has already been committed
    kv::Tx tx;
    auto view_map1 = tx.get_view(map_priv);
    auto v = view_map1->get("key1"); // v.value() == "value1"
    view_map1->remove("key1");
    auto rc = tx.commit();

    // New Transaction
    kv::Tx tx_new;
    auto view_map1_new = tx.get_view(map_priv);
    auto v1 = view_map1_new->get("key1"); // v1.has_value() == false

Global commit
-------------

A ``Map`` is globally committed at a specific :cpp:type:`kv::Version` when it is not possible to access the state of that ``Map`` prior to that version.
This is useful when it is certain that the state of the ``Store`` prior to a specific version will never need to be read or modified. A transaction is automatically globally committed once the consensus protocol has established that a majority of nodes in the CCF network have successfully committed that transaction.

The :cpp:class:`kv::Map::TxView::get_globally_committed` member function returns the value of a key that we know has been globally committed.

.. code-block:: cpp

    // Assuming that "key1":"value1" has already been committed
    auto view_map1 = tx.get_view(map_priv);

    // "key1" has not yet been globally committed
    auto v = view_map1.get_globally_committed("key1");
    assert(v.has_value() == false);

.. code-block:: cpp

    // Meanwhile, the CCF network globally commits the transaction in which "key1" was written
    auto v1 = view_map1.get_globally_committed("key1"); // v1.has_value() == "value1"
    assert(v.value() == "value1");

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

A ``View`` offers a :cpp:class:`kv::Map::TxView::foreach` member function to iterate over all the elements written to that ``Map`` so far and run a lambda function for each Key-Value pair. Note that a :cpp:class:`kv::Map::TxView::foreach` loop can be ended early by returning ``false``.

.. code-block:: cpp

    using namespace std;
    // Assuming that "key1":"value1" and "key2":"value2" have already been committed
    kv::Tx tx;
    auto view_map1 = tx.get_view(map_priv);

    // Outputs:
    //  key: key1 - value: value1
    //  key: key2 - value: value2
    view_map1->foreach([](string& key, string& value) {
        cout << " key: " << key << " - value: " << value << endl;
        return true;
        if (/* condition*/)
        {
            return false;

        }
    });

Applying and reverting writes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Changes to the ``Store`` are made by atomic transactions. For a given :cpp:class:`kv::Tx`, either all of its writes are applied, or none are. Only applied writes are replicated and may be globally committed. Transactions may be abandoned without applying their writes - their changes will never be seen by other transactions.

By default CCF decides which transactions are successful (so should be applied to the persistent store) by looking at the status code contained in the response: all transactions producing ``2xx`` status codes will be applied, while any other status code will be treated as an error and will `not` be applied to the persistent store. If this behaviour is not desired, for instance when an app wants to log incoming requests even though they produce an error, then it can be dynamically overridden by explicitly telling CCF whether it should apply a given transaction:

.. code-block:: cpp

    args.rpc_ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
    auto forbidden_requests_view = tx.get_view(forbidden_requests);

    // Log details of forbidden request
    forbidden_requests_view->put(...);

     // Apply this, even though it has an error response
    args.rpc_ctx->set_apply_writes(true);
