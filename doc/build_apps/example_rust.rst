Example app (Rust)
==================

.. note::

    The Rust application interface is experimental, not a stable or
    production-supported SDK. Use the SDK, CCF libraries and documentation from
    the same CCF revision. Older releases may not contain this interface.

CCF provides an initial Rust interface for native applications. It deliberately
exposes a small subset of the public application API:

- read-write and read-only HTTP endpoints;
- user-certificate authentication or no authentication;
- request bodies, raw queries, decoded path parameters, and named headers;
- response status, headers, body, and OData errors; and
- raw-byte KV ``get``, ``has``, ``put``, and ``remove`` operations.

Advanced endpoint configuration (including API schemas), custom authentication,
caller-identity access, historical queries, indexing, logging, crypto helpers,
and commit callbacks are not currently exposed. Do not assume that every
facility described by the C++ or JavaScript documentation is available in Rust.
See :doc:`rust_api` for the supported Rust API.

Build the sample
----------------

Start with a CCF checkout containing the Rust interface and follow
:doc:`/contribute/build_setup` to install the native build dependencies.
Rust 1.90 and Cargo are required; the sample pins its toolchain in
:ccf_repo:`samples/apps/basic_rust/rust-toolchain.toml`.

From the repository root, configure a Debug build and build the sample:

.. code-block:: bash

    cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build --target basic_rust

This produces the native executable ``build/samples/apps/basic_rust/basic_rust``,
not a JavaScript bundle or a library loaded into a running node. Use a separate
build directory if you already have a differently configured CCF build.

The sample's Cargo manifest declares a ``staticlib`` and a path dependency on
the SDK. These relative paths assume the sample's location in the CCF checkout:

.. literalinclude:: ../../samples/apps/basic_rust/Cargo.toml
    :language: toml

The CMake project links that archive into a CCF application:

.. literalinclude:: ../../samples/apps/basic_rust/CMakeLists.txt
    :language: cmake
    :start-at: cmake_minimum_required

The helper maps CMake ``Debug`` builds to Cargo's development profile and all
other build types to Cargo's release profile. It also links the generic C++ ABI
bridge, launcher, and CCF libraries. Cargo is invoked on every build and decides
whether the crate is up to date, so Rust source edits do not require CMake to be
reconfigured. ``LIB_NAME`` defaults to the package name with dashes replaced by
underscores; set it explicitly when the crate's ``[lib] name`` differs from its
package name. The application should commit ``Cargo.lock`` and pin a Rust
toolchain for reproducible builds.

Write the application
---------------------

The complete example is in :ccf_repo:`samples/apps/basic_rust/src/lib.rs`.
Its ``register`` function accepts a mutable :rustdoc:`Registry <struct.Registry.html>`
and returns ``Result<(), BridgeError>``. Registration describes the endpoints;
their closures run later, once per request (and possibly again on a retry).
At the end of the crate, the export macro supplies CCF's application entry point:

.. literalinclude:: ../../samples/apps/basic_rust/src/lib.rs
    :language: rust
    :start-at: ccf_app::export_app!

Writing a record
~~~~~~~~~~~~~~~~

The PUT handler accepts arbitrary bytes and writes them to the private
``records`` map:

.. literalinclude:: ../../samples/apps/basic_rust/src/lib.rs
    :language: rust
    :start-after: SNIPPET_START: rust_put_record
    :end-before: SNIPPET_END: rust_put_record
    :dedent: 4

``Auth::UserCert`` requires a certificate registered as a CCF user, not just any
TLS client certificate. The path is registered without the ``/app`` prefix;
clients call ``/app/records/{key}``.

``body()`` borrows bytes from the callback context. The handler copies them
before borrowing the context mutably again to obtain the decoded path parameter
and access the map. The sample's ``required_key`` helper converts a missing
parameter into an HTTP 400 :rustdoc:`EndpointError <struct.EndpointError.html>`;
``?`` propagates bridge failures as internal endpoint errors.

Reading a record
~~~~~~~~~~~~~~~~

A read-only endpoint cannot write to the store, but can still set its HTTP
response:

.. literalinclude:: ../../samples/apps/basic_rust/src/lib.rs
    :language: rust
    :start-after: SNIPPET_START: rust_get_record
    :end-before: SNIPPET_END: rust_get_record
    :dedent: 4

``get`` returns ``Ok(None)`` when a key is absent, ``Ok(Some(Vec<u8>))`` for an
owned copy of a value, or an error if access fails. An empty value is distinct
from an absent key. Here the handler returns HTTP 404 with an OData error for
absence and HTTP 200 with the original bytes otherwise.

The sample also includes deliberately failing endpoints for CCF's integration
tests. They are not part of the records API and should not be copied into a
production application.

Run and call the sample
-----------------------

From the repository root, launch a local test network using the source-tree
sandbox script:

.. code-block:: bash

    cd build
    ../tests/sandbox/sandbox.sh \
      --constitution-dir ../samples/constitutions/default \
      --package samples/apps/basic_rust/basic_rust

The sandbox opens the service and creates test user certificates. See
:doc:`run_app` for platform prerequisites, sandbox behaviour and log locations.
It is a development tool, not a production deployment procedure.

In another terminal, change to the same ``build`` directory. Use the node URL
printed by the sandbox (normally ``https://127.0.0.1:8000``):

.. code-block:: bash

    export CCF_URL=https://127.0.0.1:8000
    export CCF_COMMON=workspace/sandbox_common
    curl --cacert "$CCF_COMMON/service_cert.pem" \
      --cert "$CCF_COMMON/user0_cert.pem" --key "$CCF_COMMON/user0_privk.pem" \
      -i -X PUT "$CCF_URL/app/records/example" \
      -H "content-type: application/octet-stream" --data-binary 'hello Rust'
    curl --cacert "$CCF_COMMON/service_cert.pem" \
      --cert "$CCF_COMMON/user0_cert.pem" --key "$CCF_COMMON/user0_privk.pem" \
      -i "$CCF_URL/app/records/example"

The PUT returns HTTP 204 with no body. The GET returns HTTP 200,
``content-type: application/octet-stream``, and ``hello Rust``. Reading
``/app/records/missing`` returns HTTP 404 with error code ``ResourceNotFound``.
Omitting the client certificate and key returns HTTP 401. Stop the network with
Ctrl+C in the first terminal.

These operations are exercised by :ccf_repo:`tests/basic_rust.py`, including a
binary-value round trip. A successful write response is not itself proof of
global commitment; see :doc:`/use_apps/verify_tx` before relying on durability.

Use an installed SDK
--------------------

For an application outside the CCF source tree, first :doc:`install CCF
<install_bin>` from a revision containing the Rust interface. Copy the sample
project to your application directory, keeping its manifest, lockfile,
toolchain file, CMake file and ``src`` directory. Replace only the ``ccf-app``
dependency's path with the installed SDK path, for example:

.. code-block:: toml

    [dependencies]
    ccf-app = { path = "/opt/ccf/share/ccf/src/rust/ccf-app" }

From that application directory:

.. code-block:: bash

    cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_PREFIX_PATH=/opt/ccf
    cmake --build build --target basic_rust
    /opt/ccf/bin/sandbox.sh --package ./build/basic_rust

The CMake helper selects the installed bridge sources automatically. Adjust
``/opt/ccf`` for a different install prefix, and keep this installation paired
with the SDK used to compile the application.

Endpoint execution
------------------

Handlers may run concurrently and must implement ``Send`` and ``Sync``. CCF may also
retry a read-write handler when a transaction conflicts, so handlers should be
deterministic and should not perform non-transactional side effects.

Request and response contexts, transactions, and map handles borrow the callback
context and cannot be retained. Values returned by KV ``get`` are owned copies.
The SDK requires Rust's ``unwind`` panic strategy so that panics are caught at
the ABI boundary and become HTTP 500 errors. Builds using ``panic = "abort"``
are rejected. C++ exceptions are also contained by the bridge. When a handler
returns an ``EndpointError`` with a status that is not a known HTTP error
status, the host bridge emits HTTP 500 while preserving the error code and
message.

KV values and keys
------------------

The initial API treats keys and values as byte strings. Applications may layer
their own serializers on these operations; the ``Codec`` trait provides a
common interface without prescribing a wire format.
It does not automatically serialize map operations: call ``encode``/``decode``
explicitly and decide how decoding errors map to endpoint errors. The
:rustdoc:`Codec reference <trait.Codec.html>` includes an example. Treat your
key/value encoding and its evolution as part of your application's ledger
format; changing Rust types alone does not migrate stored data.

Map names retain the standard CCF security semantics. Names beginning with
``public:`` are written to the ledger in plaintext. All other application map
names, such as the sample's ``records`` map, are private and encrypted. Like
native C++ applications, native Rust applications are trusted code: raw map
access does not enforce the namespace restrictions applied to JavaScript
applications for reserved governance and internal maps.

Read-only handlers receive only ``ReadOnlyMap``, so write operations are
not available at compile time. Errors returned by a handler use the normal CCF
transaction semantics: unsuccessful responses discard writes.

Develop and check changes
-------------------------

For a quick Rust-only type check, run this from the sample directory:

.. code-block:: bash

    cargo check --locked --lib

This does not link the C++ bridge or exercise a network. Rebuild the CMake
``basic_rust`` target for a runnable application. With the CCF test build
configured, the existing integration test can be run from its build directory:

.. code-block:: bash

    ./tests.sh -R '^e2e_basic_rust$' --no-tests=error --output-on-failure

See :doc:`rust_api` for method contracts and :doc:`/contribute/build_ccf` for
documentation checks.
