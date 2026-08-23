Example app (Rust)
==================

CCF provides an initial Rust interface for native applications. It deliberately
exposes a small subset of the public application API:

- read-write and read-only HTTP endpoints;
- user-certificate authentication or no authentication;
- request bodies, raw queries, decoded path parameters, and named headers;
- response status, headers, body, and OData errors; and
- raw-byte KV ``get``, ``has``, ``put``, and ``remove`` operations.

Advanced endpoint configuration, custom authentication, historical queries,
indexing, and commit callbacks are not currently exposed.

Build
-----

Rust 1.90 and Cargo are required. A Rust application is a ``staticlib`` crate
which depends on the installed or source-tree ``ccf-rs`` crate. Its CMake file
registers the crate with ``add_ccf_rust_app``:

.. code-block:: cmake

    add_ccf_rust_app(
      my_app
      MANIFEST_PATH ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
      PACKAGE my-app
    )

The helper maps CMake ``Debug`` builds to Cargo's development profile and all
other build types to Cargo's release profile. It also links the generic C++ ABI
bridge, launcher, and CCF libraries. Cargo sources, the manifest, and the lock
file are build dependencies. The application should commit ``Cargo.lock`` and
pin a Rust toolchain for reproducible builds.

The complete records example is in :ccf_repo:`samples/apps/basic_rust`. It
exports a registration function with ``ccf_rs::export_app!`` and registers
handlers through ``Registry::read_write`` and ``Registry::read_only``.

Endpoint execution
------------------

Handlers may run concurrently and must be ``Send`` and ``Sync``. CCF may also
retry a read-write handler when a transaction conflicts, so handlers should be
deterministic and should not perform non-transactional side effects.

Request, response, transaction, and map values borrow the callback context and
cannot be retained. Rust panics are caught at the ABI boundary and become HTTP
500 errors. C++ exceptions are also contained by the bridge.

KV values and keys
------------------

The initial API treats keys and values as byte strings. Applications may layer
their own serializers on these operations; the ``Codec`` trait provides a
common interface without prescribing a wire format.

Map names retain the standard CCF security semantics. Names beginning with
``public:`` are written to the ledger in plaintext. All other application map
names, such as the sample's ``records`` map, are private and encrypted. The
framework continues to enforce reserved governance and internal map namespaces.

Read-only handlers receive only ``ReadOnlyMap``, so write operations are
not available at compile time. Errors returned by a handler use the normal CCF
transaction semantics: unsuccessful responses discard writes.
