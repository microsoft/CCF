Key-Value Store How-To
======================

The `Key-Value Store` (KV) consists of a set of :cpp:type:`kv::Map` objects that are available to the endpoints of an application. Endpoint handlers create handles which allow them to read and write from these :cpp:type:`kv::Map` objects. The framework handles conflicts between concurrent execution of multiple transactions, and produces a consistent order of transactions which is replicated between nodes, allowing the entries to be read from multiple nodes. This page outlines the core concepts and C++ APIs used to interact with the KV.

Map Naming
----------

A :cpp:type:`kv::Map` (often referred to as a `Table`) is a collection of key-value pairs of a given type. The :cpp:type:`kv::Map` itself is identified by its name, which is used to lookup the map :cpp:type:`kv::Map` from the local store during a transaction.

If a :cpp:type:`kv::Map` with the given name did not previously exist, it will be created in this transaction.

A :cpp:type:`kv::Map` can either be created as private (default) or public. Public map's names begin with a ``public:`` prefix, any any other name indicates a private map. For instance the name ``public:foo`` to a public map, while ``foo`` refers to a private map. Transactions on private maps are written to the ledger in encrypted form and can only be decrypted in the enclave of nodes that have joined the network. Transactions on public maps are written to the ledger as plaintext and can be read from outside the enclave; only their integrity is protected. The security domain of a map (public or private) cannot be changed after its creation, since this is encoded in the map's name. Public and private maps with similar names in different domains are distinct; writes to ``public:foo`` have no impact on ``foo``, and vice versa.

Transaction Semantics
---------------------

A transaction (:cpp:class:`kv::Tx`) encapsulates an individual endpoint invocation's atomic interaction with the KV. Transactions may read from and write to multiple :cpp:type:`kv::Map`, and each is automatically ordered, applied, serialised, and committed by the framework.

A reference to a new :cpp:class:`kv::Tx` is passed to each endpoint handler, and used to interact with the KV.

Each :cpp:class:`kv::Tx` gets a consistent, opaque view of the KV, including the values which have been left by previous writes. Any writes produced by this transaction will be visible to all future transactions.

When the endpoint handler indicates that its :cpp:class:`kv::Tx` should be applied (see :ref:`this section <build_apps/kv/kv_how_to:Applying and reverting writes>` for details), the executing node attempts to apply the changes to its local KV. If this produces conflicts with concurrently executing transactions, it will be automatically re-executed. Once the transaction is applied successfully, it is automatically replicated to other nodes and will, if the network is healthy, eventually be committed.

For each :cpp:type:`kv::Map` that a transaction wants to write to or read from, a :cpp:class:`kv::MapHandle` must first be acquired. These are acquired from the :cpp:func:`kv::Tx::rw` (`read-write`) method. These may be acquired either by name (in which case the desired type must be explicitly specified as a template parameter), or by using a :cpp:type:`kv::Map` instance which defines both the map's name and key-value types.

By name:

.. code-block:: cpp

    // Handle for map1
    auto map1_handle = tx.rw<kv::Map<string, string>>("map1");

    // Handles for 2 other maps, one public and one private, with different types
    auto map2_handle = tx.rw<kv::Map<string, uint64_t>>("public:map2");
    auto map3_handle = tx.rw<kv::Map<uint64_t, MyCustomClass>>("map3");

By :cpp:type:`kv::Map`:

.. code-block:: cpp

    kv::Map<string, string> map_priv("map1");
    auto map1_handle = tx.rw(map_priv);

    kv::Map<string, uint64_t> map_pub("public:map2");
    auto map2_handle = tx.rw(map_pub);

    kv::Map<uint64_t, MyCustomClass> map_priv_int("map3");
    auto map3_handle = tx.rw(map_priv_int);

The latter approach introduces a named binding between the map's name and the types of its keys and values, reducing the chance for errors where code attempts to read a map with the wrong type.

.. note:: As mentioned above, there is no need to explicitly declare a :cpp:type:`kv::Map` before it is used. The first write to a :cpp:type:`kv::Map` implicitly creates it in the underlying KV. Within a transaction, a newly created :cpp:type:`kv::Map` behaves exactly the same as an existing :cpp:type:`kv::Map` with no keys - the framework views these as semantically identical, and offers no way for the application logic to tell them apart. Any writes to a newly created :cpp:type:`kv::Map` will be persisted when the transaction commits, and future transactions will be able to access this :cpp:type:`kv::Map` by name to read those writes.

Accessing Map content via a Handle
----------------------------------

Once a :cpp:class:`kv::MapHandle` on a specific :cpp:type:`kv::Map` has been obtained, it is possible to:

- test (:cpp:func:`kv::ReadableMapHandle::has`) whether a key has any associated value;
- read (:cpp:func:`kv::ReadableMapHandle::get`) the value associated with a key;
- write (:cpp:func:`kv::WriteableMapHandle::put`) a new value for a key;
- delete (:cpp:func:`kv::WriteableMapHandle::remove`) a key and its current value;
- iterate (:cpp:func:`kv::ReadableMapHandle::foreach`) through all key-value pairs.

.. code-block:: cpp

    // Writing to a handle
    map1_handle1->put("key1", "value1");

    // Reading presence of a key
    bool has_key_1 = map1_handle->has("key1");
    assert(has_key_1);

    // Reading a value
    std::optional<std::string> read_val = map1_handle1->get("key1");
    assert(read_val.has_value());
    assert(read_val.value() == "value1");

    // Deleting a key
    map1_handle1->remove("key1");

    // Reading a deleted/non-existent key
    assert(!map_handle1->has("key1"));
    read_val = map1_handle1->get("key1");
    assert(!read_val.has_value());

Read/Write safety
-----------------

If you are only reading from or only writing to a given :cpp:type:`kv::Map` you can retrieve a `read-only` or `write-only` handle for it. This will turn unexpected reads/writes (which would introduce unintended dependencies between transactions) into compile-time errors. Instead of calling :cpp:func:`kv::Tx::rw` to get a handle which can both read and write, you can call :cpp:func:`kv::ReadOnlyTx::ro` to acquire a `read-only` handle or :cpp:func:`kv::Tx::wo` to acquire a `write-only` handle.

.. code-block:: cpp

    // Read-only handle for map_priv
    auto map1_handle_ro = tx.ro(map_priv);

    // Reading from that handle
    auto v1 = map1_handle_ro->get("key1");
    assert(v1.value() == "value1");

    // Writes are blocked at compile time
    map1_handle_ro->put("key1", "value2"); // Does not compile
    map1_handle_ro->remove("key1"); // Does not compile


    // Write-only handle for the same map
    auto map1_handle_wo = tx.wo(map_priv);

    // Write to that handle
    map1_handle_wo->put("key1", "value2");

    // Reads are blocked at compile time
    map1_handle_wo->has("key1"); // Does not compile
    map1_handle_wo->get("key1"); // Does not compile

Note that, as in the sample above, it is possible to acquire different kinds of handles at different points within your transaction's execution. So if you need to read in one location and write in another you can retrieve multiple distinct handles and get local type-safety, while the resulting transaction correctly handles all reads and writes made.

Removing a key
--------------

If a Key-Value pair was written to a :cpp:type:`kv::Map` by a previous :cpp:class:`kv::Tx`, it is possible to delete this key. Because of the append-only nature of the KV, this Key-Value pair is not actually removed from the :cpp:type:`kv::Map` but instead explicitly marked as deleted in the version that the deleting :cpp:class:`kv::Tx` is applied at.

.. code-block:: cpp

    // In transaction A, assuming that "key1" has already been written to
    auto handle = tx.rw(map_priv);
    auto v = handle->get("key1"); // v.value() == "value1"
    handle->remove("key1");
    auto rc = tx.commit();

    // In a later transaction B, which sees the state after A is applied
    auto handle = tx.rw(map_priv);
    auto v1 = handle->get("key1"); // v1.has_value() == false

Global commit
-------------

A transaction is automatically (globally) committed once the consensus protocol has established that a majority of nodes in the CCF network have successfully received and acknowledged that transaction. To operate on durable state, an application may want to query the globally committed state rather than the *current* state of the KV.

The :cpp:func:`kv::MapHandle::get_globally_committed` member function returns the value of a key that we know has been globally committed.

.. code-block:: cpp

    // Assuming that "key1":"value1" has already been committed
    auto handle = tx.rw(map_priv);

    // "key1" has not yet been globally committed
    auto v = handle.get_globally_committed("key1");
    assert(v.has_value() == false);

.. code-block:: cpp

    // Meanwhile, the CCF network globally commits the transaction in which "key1" was written
    auto v1 = handle.get_globally_committed("key1"); // v1.has_value() == "value1"
    assert(v.value() == "value1");

----------

Miscellaneous
-------------

``foreach()``
~~~~~~~~~~~~~

Values can only be retrieved directly (:cpp:func:`kv::MapHandle::get`) for a given target key. However, it is sometimes necessary to access unknown keys, or to iterate through all Key-Value pairs.

CCF offers a member function :cpp:func:`kv::MapHandle::foreach` to iterate over all the elements written to that :cpp:type:`kv::Map` so far, and run a lambda function for each Key-Value pair. Note that a :cpp:class:`kv::MapHandle::foreach` loop can be ended early by returning ``false`` from this lambda, while ``true`` should be returned to continue iteration.

.. code-block:: cpp

    using namespace std;

    // Assuming that "key1":"value1" and "key2":"value2" have already been committed
    auto handle = tx.rw(map_priv);

    // Outputs:
    //  key: key1 - value: value1
    //  key: key2 - value: value2
    handle->foreach([](const string& key, const string& value) {
        cout << " key: " << key << " - value: " << value << endl;
        return true;
        if (/* condition*/)
        {
            return false;
        }
    });

Applying and reverting writes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Changes to the KV are made by atomic transactions. For a given :cpp:class:`kv::Tx`, either all of its writes are applied, or none are. Only applied writes are replicated and may be globally committed. Transactions may be abandoned without applying their writes - their changes will never be seen by other transactions.

By default CCF decides which transactions are successful (so should be applied to the persistent store) by looking at the status code contained in the response: all transactions producing ``2xx`` status codes will be applied, while any other status code will be treated as an error and will `not` be applied to the persistent store. If this behaviour is not desired, for instance when an app wants to log incoming requests even though they produce an error, then it can be dynamically overridden by explicitly telling CCF whether it should apply a given transaction:

.. code-block:: cpp

    args.rpc_ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
    auto handle = tx.rw(forbidden_requests);

    // Log details of forbidden request
    handle->put(...);

     // Apply this, even though it has an error response
    args.rpc_ctx->set_apply_writes(true);
