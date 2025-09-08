// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ds/actors.h"
#include "ds/internal_logger.h"

namespace ccf
{
  UserEndpointRegistry::UserEndpointRegistry(
    ccf::AbstractNodeContext& context) :
    CommonEndpointRegistry(get_actor_prefix(ActorsType::users), context)
  {}

  void UserEndpointRegistry::handle_event_request_completed(
    const ccf::endpoints::RequestCompletedEvent& event)
  {}

  void UserEndpointRegistry::handle_event_dispatch_failed(
    const ccf::endpoints::DispatchFailedEvent& event)
  {
    CCF_APP_INFO("DispatchFailedEvent: {} {}", event.method, event.status);
  }
}