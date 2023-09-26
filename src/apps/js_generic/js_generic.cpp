// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/js_openenclave_plugin.h"
#include "ccf/js_snp_attestation_plugin.h"
#include "js_generic_base.h"

namespace ccfapp
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccfapp::AbstractNodeContext& context)
  {
    return make_user_endpoints_impl(context);
  }

  std::vector<ccf::js::FFIPlugin> get_js_plugins()
  {
#ifdef SGX_ATTESTATION_VERIFICATION
    return {ccf::js::openenclave_plugin, ccf::js::snp_attestation_plugin};
#else
    return {ccf::js::snp_attestation_plugin};
#endif
  }

} // namespace ccfapp
