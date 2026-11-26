The `ccf/node/configuration.h` header and its `ccf::CCFConfig` type are no longer part of the public API.
`ccf::NodeConfigurationInterface::get()` and `ccf::NodeConfigurationState` have been removed; applications should call `ccf::NodeConfigurationInterface::get_node_data()` to read the operator-provided node data.
