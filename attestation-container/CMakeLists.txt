# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# For now, copy .proto files across to external executor test
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/attestation-container.proto
    ${CCF_DIR}/tests/external_executor/executors/attestation_container/protobuf/attestation-container.proto
    COPYONLY
)

# Note: can be removed once all external executors are containerised
# and ccf/registration.py is no longer imported by main test code
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/attestation-container.proto
    ${CCF_DIR}/src/apps/external_executor/protobuf/attestation-container.proto
    COPYONLY
)