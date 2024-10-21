// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <span>

namespace ccf::cose::edit
{
    static void insert_receipt_in_uhdr(const std::span<const uint8_t>& buf_);
}