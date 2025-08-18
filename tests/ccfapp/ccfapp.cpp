// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/version.h"

#include <iostream>

using namespace std;
using namespace nlohmann;

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<ccf::UserEndpointRegistry>(context);
  }
}

int main()
{
  std::cout << "I'm a CCF test app " << ccf::ccf_version << std::endl;
}