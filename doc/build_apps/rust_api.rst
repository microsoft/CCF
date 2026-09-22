Rust API reference
==================

The :rustdoc:`ccf_app crate <index.html>` is the safe application-author API.
Its reference is generated from the SDK in the same CCF documentation version,
not from the latest SDK on another site. The interface is experimental; see
:doc:`example_rust` for a complete build/run walkthrough and current limits.

.. list-table::
    :header-rows: 1
    :widths: 25 75

    * - Task
      - API
    * - Register and export endpoints
      - :rustdoc:`Registry <struct.Registry.html>`,
        :rustdoc:`export_app! <macro.export_app.html>`,
        :rustdoc:`RetrySafeHandler <trait.RetrySafeHandler.html>`
    * - Choose authentication
      - :rustdoc:`Auth <enum.Auth.html>`
    * - Read requests and write responses
      - :rustdoc:`ReadOnlyContext <struct.ReadOnlyContext.html>`,
        :rustdoc:`WriteContext <struct.WriteContext.html>`
    * - Access transactional state
      - :rustdoc:`ReadOnlyMap <struct.ReadOnlyMap.html>`,
        :rustdoc:`Map <struct.Map.html>`
    * - Define serialization
      - :rustdoc:`Codec <trait.Codec.html>`
    * - Report failures
      - :rustdoc:`BridgeError <enum.BridgeError.html>`,
        :rustdoc:`BridgeResult <type.BridgeResult.html>`,
        :rustdoc:`EndpointError <struct.EndpointError.html>`,
        :rustdoc:`EndpointResult <type.EndpointResult.html>`

Start with :rustdoc:`Registry::read_write
<struct.Registry.html#method.read_write>` or :rustdoc:`Registry::read_only
<struct.Registry.html#method.read_only>`. Contexts and map handles are borrowed
for a single callback, not reusable connections to the store. In particular,
:rustdoc:`ReadOnlyMap::get <struct.ReadOnlyMap.html#method.get>` distinguishes a
missing key from a bridge error.

The C ABI in :ccf_repo:`include/ccf/rust_ffi.h` and the SDK's hidden raw types
are bridge implementation details, not the interface applications should call.
Using ``export_app!`` does not require writing unsafe Rust or invoking C
functions directly.
