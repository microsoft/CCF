// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the shared error/byte-buffer C ABI (tav/utils.h).

#include "support.h"

TEST_CASE("utils: error accessors are defensive against NULL") {
    CHECK(tav_error_code(nullptr) == TAV_ERROR_IS_NULL);

    const char *message = tav_error_message(nullptr);
    REQUIRE(message != nullptr);
    CHECK(std::string(message) == "null TavError pointer");

    // Freeing a NULL error is a documented no-op.
    tav_error_free(nullptr);
}

TEST_CASE("utils: NULL byte-buffer accessors and free are no-ops") {
    tav_byte_buffer_free(nullptr);
    CHECK(tav_byte_buffer_data(nullptr) == nullptr);
    CHECK(tav_byte_buffer_len(nullptr) == 0);
}
