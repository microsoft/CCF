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
which depends on the source-tree ``src/rust/ccf-app`` crate or the installed
``share/ccf/src/rust/ccf-app`` crate. Its CMake file registers the crate with
``add_ccf_rust_app``:

.. code-block:: cmake

    add_ccf_rust_app(
      my_app
      MANIFEST_PATH ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
      PACKAGE my-app
    )

The helper maps CMake ``Debug`` builds to Cargo's development profile and all
other build types to Cargo's release profile. It also links the generic C++ ABI
bridge, launcher, and CCF libraries. Cargo is invoked on every build and decides
whether the crate is up to date, so Rust source edits do not require CMake to be
reconfigured. ``LIB_NAME`` defaults to the package name with dashes replaced by
underscores; set it explicitly when the crate's ``[lib] name`` differs from its
package name. The application should commit ``Cargo.lock`` and pin a Rust
toolchain for reproducible builds.

The complete records example is in :ccf_repo:`samples/apps/basic_rust`. It
exports a registration function with ``ccf_app::export_app!`` and registers
handlers through ``Registry::read_write`` and ``Registry::read_only``.

Endpoint execution
------------------

Handlers may run concurrently and must be ``Send`` and ``Sync``. CCF may also
retry a read-write handler when a transaction conflicts, so handlers should be
deterministic and should not perform non-transactional side effects.

Request and response contexts, transactions, and map handles borrow the callback
context and cannot be retained. Values returned by KV ``get`` are owned copies.
The SDK requires Rust's ``unwind`` panic strategy so that panics are caught at
the ABI boundary and become HTTP 500 errors. Builds using ``panic = "abort"``
are rejected. C++ exceptions are also contained by the bridge.

KV values and keys
------------------

The initial API treats keys and values as byte strings. Applications may layer
their own serializers on these operations; the ``Codec`` trait provides a
common interface without prescribing a wire format.

Map names retain the standard CCF security semantics. Names beginning with
``public:`` are written to the ledger in plaintext. All other application map
names, such as the sample's ``records`` map, are private and encrypted. Like
native C++ applications, native Rust applications are trusted code: raw map
access does not enforce the namespace restrictions applied to JavaScript
applications for reserved governance and internal maps.

Read-only handlers receive only ``ReadOnlyMap``, so write operations are
not available at compile time. Errors returned by a handler use the normal CCF
transaction semantics: unsuccessful responses discard writes.
