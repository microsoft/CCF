Rust API reference
==================

The :rustdoc:`ccf_app <index.html>` crate reference is generated from the SDK in the same CCF version as this documentation.
The Rust interface is experimental; see :doc:`example_rust` for a walkthrough and a list of unsupported features.

- Endpoints: :rustdoc:`Registry <struct.Registry.html>`, :rustdoc:`export_app! <macro.export_app.html>`, :rustdoc:`Auth <enum.Auth.html>`, :rustdoc:`RetrySafeHandler <trait.RetrySafeHandler.html>`
- Requests and responses: :rustdoc:`ReadOnlyContext <struct.ReadOnlyContext.html>`, :rustdoc:`WriteContext <struct.WriteContext.html>`
- Key-value store: :rustdoc:`ReadOnlyMap <struct.ReadOnlyMap.html>`, :rustdoc:`Map <struct.Map.html>`, :rustdoc:`Codec <trait.Codec.html>`
- Errors: :rustdoc:`BridgeError <enum.BridgeError.html>`, :rustdoc:`EndpointError <struct.EndpointError.html>`

Applications do not need unsafe code: the C ABI in :ccf_repo:`include/ccf/rust_ffi.h` is an implementation detail of the SDK.
