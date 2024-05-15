// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/endpoint.h"

#include <string>
#include <map>

namespace ccf::js
{

    struct Metadata
    {
        std::map<std::string, std::map<std::string, ccf::endpoints::EndpointProperties>> endpoints;
    };
    DECLARE_JSON_TYPE(Metadata);
    DECLARE_JSON_REQUIRED_FIELDS(Metadata, endpoints);

    struct Bundle
    {
        std::map<std::string, std::string> modules;
        Metadata metadata;
    };

    DECLARE_JSON_TYPE(Bundle);
    DECLARE_JSON_REQUIRED_FIELDS(Bundle, modules, metadata);

    struct BundleWrapper
    {
        Bundle bundle;
    };

    DECLARE_JSON_TYPE(BundleWrapper);
    DECLARE_JSON_REQUIRED_FIELDS(BundleWrapper, bundle);
}