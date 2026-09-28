Example app (Rust)
==================

.. warning:: The Rust interface is **experimental** and is not covered by the API stability commitments in :doc:`release_policy`. Its Rust API, C ABI and build integration may change incompatibly in any release, so use the SDK, CCF libraries and documentation from the same CCF revision.

The Rust SDK, the ``ccf-app`` crate, exposes a small subset of the native application API: read-only and read-write endpoints, user-certificate or no authentication, request and response access, OData errors, and raw-byte KV ``get``, ``has``, ``put`` and ``remove``.
API schemas, custom authentication, caller identity, historical queries, indexing, logging, crypto helpers and commit callbacks are not exposed.
See the :doc:`API reference <rust_api>` for details.

Build
-----

Install the :doc:`build dependencies </contribute/build_setup>` and Rust 1.90, then build the sample from the repository root:

.. code-block:: bash

    cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build --target basic_rust

This produces the executable ``build/samples/apps/basic_rust/basic_rust``.
The application is a ``staticlib`` crate that depends on the SDK:

.. literalinclude:: ../../samples/apps/basic_rust/Cargo.toml
    :language: toml

``add_ccf_rust_app`` builds the crate and links it with CCF's C++ bridge and launcher:

.. literalinclude:: ../../samples/apps/basic_rust/CMakeLists.txt
    :language: cmake
    :start-at: cmake_minimum_required

Cargo runs on every build with ``--locked``, so commit ``Cargo.lock``.
CMake ``Debug`` builds use Cargo's ``dev`` profile, and other build types use ``release``.
``LIB_NAME`` must match the crate's ``[lib] name``, and defaults to ``PACKAGE`` with dashes replaced by underscores.
Add other Rust code as Cargo dependencies, not as separate ``staticlib`` archives, which may export duplicate runtime symbols.
For a quick type check without linking, run ``cargo check --locked --lib`` in the crate directory.

Write the application
---------------------

:ccf_repo:`samples/apps/basic_rust/src/lib.rs` defines ``fn register(registry: &mut Registry) -> Result<(), BridgeError>``, which installs handlers on the :rustdoc:`Registry <struct.Registry.html>`, and exports it with :rustdoc:`export_app! <macro.export_app.html>`:

.. literalinclude:: ../../samples/apps/basic_rust/src/lib.rs
    :language: rust
    :start-at: ccf_app::export_app!

This read-write handler stores the request body under the ``key`` path parameter:

.. literalinclude:: ../../samples/apps/basic_rust/src/lib.rs
    :language: rust
    :start-after: SNIPPET_START: rust_put_record
    :end-before: SNIPPET_END: rust_put_record
    :dedent: 4

Paths exclude the ``/app`` prefix, and ``Auth::UserCert`` accepts only certificates registered as CCF users.
The body is borrowed from the context, so it is copied before ``path_param``, which takes ``&mut self``.
``?`` turns any :rustdoc:`BridgeError <enum.BridgeError.html>` into HTTP 500, so client errors are returned explicitly as an :rustdoc:`EndpointError <struct.EndpointError.html>`, as the sample's ``required_key`` helper does for a missing key.

This read-only handler returns the stored value, or HTTP 404 if there is none:

.. literalinclude:: ../../samples/apps/basic_rust/src/lib.rs
    :language: rust
    :start-after: SNIPPET_START: rust_get_record
    :end-before: SNIPPET_END: rust_get_record
    :dedent: 4

The sample's other endpoints exist only for CCF's end-to-end tests, and several are unauthenticated, so remove them from any copy.

Run the sample
--------------

Start a :doc:`sandbox network <run_app>`:

.. code-block:: bash

    cd build
    ../tests/sandbox/sandbox.sh --package samples/apps/basic_rust/basic_rust

From another terminal in the same directory, write and read a record as ``user0``:

.. code-block:: bash

    export CCF_URL=https://127.0.0.1:8000 # As printed by the sandbox
    export CCF_COMMON=workspace/sandbox_common
    curl --cacert "$CCF_COMMON/service_cert.pem" \
      --cert "$CCF_COMMON/user0_cert.pem" --key "$CCF_COMMON/user0_privk.pem" \
      -i -X PUT "$CCF_URL/app/records/example" \
      -H "content-type: application/octet-stream" --data-binary 'hello Rust'
    curl --cacert "$CCF_COMMON/service_cert.pem" \
      --cert "$CCF_COMMON/user0_cert.pem" --key "$CCF_COMMON/user0_privk.pem" \
      -i "$CCF_URL/app/records/example"

The PUT returns HTTP 204, and the GET returns HTTP 200 with the body ``hello Rust``.
A missing key returns HTTP 404, and a request without the user certificate returns HTTP 401.
A successful response does not mean that the write is committed; see :doc:`/use_apps/verify_tx`.
These requests are also covered by the ``e2e_basic_rust`` test in :ccf_repo:`tests/basic_rust.py`.

Use an installed SDK
--------------------

To build outside the CCF source tree, :doc:`install CCF <install_bin>`, copy the sample project without its test-only endpoints, and point its ``ccf-app`` dependency at the installed SDK:

.. code-block:: toml

    ccf-app = { path = "/opt/ccf/share/ccf/src/rust/ccf-app" }

Then build and run it with the same installation:

.. code-block:: bash

    cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_PREFIX_PATH=/opt/ccf
    cmake --build build --target basic_rust
    /opt/ccf/bin/sandbox.sh --package "$PWD/build/basic_rust"

Handler rules
-------------

- CCF may run handlers concurrently, and re-execute them after a transaction conflict, so any side effects outside the KV must be safe to repeat. Handlers must implement the :rustdoc:`RetrySafeHandler <trait.RetrySafeHandler.html>` marker trait, which every ``Send + Sync`` type does, and be ``'static``.
- Contexts and map handles are only valid during one handler call. Values returned by ``get`` are owned copies.
- KV writes are applied only if the response status is 2xx.
- An :rustdoc:`EndpointError <struct.EndpointError.html>` whose status is not a known HTTP error status is sent as HTTP 500, with its code and message.
- Panics are caught and sent as HTTP 500, which requires ``panic = "unwind"``. ``export_app!`` keeps panic messages from application code out of node output, which is visible to the host, and custom panic hooks must not print confidential data either.
- Keys and values are raw bytes; maps never apply a :rustdoc:`Codec <trait.Codec.html>` implicitly, and the chosen encoding is part of the application's ledger format.
- Maps whose names start with ``public:`` are stored in the ledger in plaintext, and all other maps are encrypted. Like C++ applications, Rust applications are trusted code and are not prevented from accessing governance or internal maps.
