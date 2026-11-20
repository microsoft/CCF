The C++ SDK breaks public-header dependency cycles by relocating transaction, endpoint and base64 headers, moving base64 functions from `ccf::crypto` to `ccf::ds`, and dropping some transitive includes.
See the [migration guide](doc/releases/migration_7_x_to_8_x.rst#public-c-headers) for replacement includes.
