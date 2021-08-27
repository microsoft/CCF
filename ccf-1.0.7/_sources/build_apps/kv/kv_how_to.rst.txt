Key-Value Store How-To
======================

The Key-Value :cpp:class:`kv::Store` is a collection of :cpp:class:`kv::Map` objects that are available from all the end-points of an application. There is one unique ``Store`` created in the enclave of each node that is passed to the constructor of all applications.

.. code-block:: cpp

    Store tables;

Creating a Map
--------------

A :cpp:type:`kv::Map` (often referred to as a ``Table``) is a collection of key-value pairs of a given type. The :cpp:type:`kv::Map` itself is identified by its name, which is used to lookup the map :cpp:type:`kv::Map` in a :cpp:class:`kv::Store` during a transaction.

If a ``Map`` with the given name did not previously exist, it will be created in this transaction..

A ``Map`` can either be created as private (default) or public. Public map's names begin with a ``public:`` prefix, any any other name indicates a private map. Transactions on private maps are written to the ledger in encrypted form and can only be decrypted in the enclave of the nodes that have joined the network. Transactions on public maps are written to the ledger as plaintext and can be read from outside the enclave (only their integrity is protected). The security domain of a map (public or private) cannot be changed after its creation, since this is encoded in the map's name. Public and private maps with similar names are distinct; writes to "public:foo" have no impact on "foo", and vice versa.


Accessing the Transaction
-------------------------

A :cpp:class:`kv::Tx` corresponds to the atomic operations that can be executed on the Key-Value ``Store``. A transaction can affect one or multiple ``Map`` and are automatically committed by CCF once the endpoint's handler returns successfully.

A single ``Transaction`` (``tx``) is passed to each endpoint of an application and should be used to interact with the Key-Value ``Store``.

When the end-point successfully completes, the node on which the end-point was triggered attempts to commit the transaction to apply the changes to the Store. Once the transaction is committed successfully, it is automatically replicated by CCF and should globally commit.

For each :cpp:type:`kv::Map` that a transaction wants to write to or read from, a :cpp:class:`kv::MapHandle` must first be acquired. These are acquired from the :cpp:func:`kv::Tx::rw` (`read-write`) method. These may be acquired either by name (in which case the desired type must be explicitly specified as a template parameter), or by using a :cpp:type:`kv::Map` instance which defines both the map's name and key-value types.

By name:

.. code-block:: cpp

    // Handle for map1
    auto map1_handle = tx.rw<kv::Map<string, string>>("map1");

    // Handles for 2 other maps, one public and one private, with different types
    auto map2_handle = tx.rw<kv::Map<string, uint64_t>>("public:map2");
    auto map3_handle = tx.rw<kv::Map<uint64_t, MyCustomClass>>("map3");

By ``Map``:

.. code-block:: cpp

    kv::Map<string, string> map_priv("map1");
    auto map1_handle = tx.rw(map_priv);

    kv::Map<string, stuint64_tring> map_pub("public:map2");
    auto map2_handle = tx.rw(map_pub);

    kv::Map<uint64_t, string> MyCustomClass("map3");
    auto map3_handle = tx.rw(map_priv_int);

The latter approach introduces a named binding between the map's name and the types of its keys and values, reducing the chance for errors where code attempts to read a map with the wrong type.

As noted above, this access may cause the ``Map`` to be created, if it did not previously. In fact all ``Maps`` are created like this, in the first transaction in which they are written to. Within a transaction, a newly created ``Map`` behaves exactly the same as an existing ``Map`` with no keys - the framework views these as semantically identical, and offers no way for the application logic to tell them apart. Any writes to a newly created ``Map`` will be persisted when the transaction commits, and future transactions will be able to access this ``Map`` by name to read those writes.


Accessing Map content via a Handle
----------------------------------

Once a :cpp:class:`kv::MapHandle` on a specific :cpp:type:`kv::Map` has been obtained, it is possible to:

- test (:cpp:func:`kv::MapHandle::has`) whether a key has any associated value;
- read (:cpp:func:`kv::MapHandle::get`) the value associated with a key;
- write (:cpp:func:`kv::MapHandle::put`) a new value for a key;
- delete (:cpp:func:`kv::MapHandle::remove`) a key and its current value;
- iterate (:cpp:func:`kv::MapHandle::foreach`) through all key-value pairs.

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

If you are only reading from or only writing to a given :cpp:type:`kv::Map` you can retrieve a `read-only` or `write-only` handle for it, turning unexpected reads/writes (which would introduce unintended dependencies between transactions) into compile-time errors. Instead of calling :cpp:func:`kv::Tx::rw` to get a handle which can both read and write, you can call :cpp:func:`kv::Tx::ro` to acquire a read-only handle or :cpp:func:`kv::Tx::wo` to acquire a write-only handle.

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

If a Key-Value pair was written to a ``Map`` by a previous ``Transaction``, it is possible to delete this key. Because of the append-only nature of the ``Store``, this Key-Value pair is not actually removed from the ``Map`` but instead explicitly marked as deleted from the version that the corresponding ``Transaction`` is committed at.

.. code-block:: cpp

    // In transaction A, assuming that "key1" has already been committed
    auto handle = tx.rw(map_priv);
    auto v = handle->get("key1"); // v.value() == "value1"
    handle->remove("key1");
    auto rc = tx.commit();

    // In a later transaction B, which sees the state after A is applied
    auto handle = tx.rw(map_priv);
    auto v1 = handle->get("key1"); // v1.has_value() == false

Global commit
-------------

A ``Map`` is globally committed at a specific :cpp:type:`kv::Version` when it is not possible to access the state of that ``Map`` prior to that version.
This is useful when it is certain that the state of the ``Store`` prior to a specific version will never need to be read or modified. A transaction is automatically globally committed once the consensus protocol has established that a majority of nodes in the CCF network have successfully received and acknowledged that transaction.

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

CCF offers a member function :cpp:func:`kv::MapHandle::foreach` to iterate over all the elements written to that ``Map`` so far, and run a lambda function for each Key-Value pair. Note that a :cpp:class:`kv::MapHandle::foreach` loop can be ended early by returning ``false`` from this lambda, while ``true`` should be returned to continue iteration.

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

Changes to the ``Store`` are made by atomic transactions. For a given :cpp:class:`kv::Tx`, either all of its writes are applied, or none are. Only applied writes are replicated and may be globally committed. Transactions may be abandoned without applying their writes - their changes will never be seen by other transactions.

By default CCF decides which transactions are successful (so should be applied to the persistent store) by looking at the status code contained in the response: all transactions producing ``2xx`` status codes will be applied, while any other status code will be treated as an error and will `not` be applied to the persistent store. If this behaviour is not desired, for instance when an app wants to log incoming requests even though they produce an error, then it can be dynamically overridden by explicitly telling CCF whether it should apply a given transaction:

.. code-block:: cpp

    args.rpc_ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
    auto handle = tx.rw(forbidden_requests);

    // Log details of forbidden request
    handle->put(...);

     // Apply this, even though it has an error response
    args.rpc_ctx->set_apply_writes(true);
