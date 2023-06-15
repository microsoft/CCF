// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  void init_proposals_handlers(ccf::BaseEndpointRegistry& registry)
  {
    //// implementation of TSP interface Proposals
    auto create_proposal =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals:create",
        HTTP_POST,
        json_adapter(json_api_version_adapter(create_proposal)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto withdraw_proposal =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}:withdraw",
        HTTP_POST,
        json_adapter(json_api_version_adapter(withdraw_proposal)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_proposal =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(get_proposal)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto list_proposals =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(list_proposals)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_actions =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}/actions",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(get_actions)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    //// implementation of TSP interface Ballots
    auto submit_ballot = [&](
                           ccf::endpoints::EndpointContext& ctx,
                           nlohmann::json&& params,
                           ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::v0_0_1_preview:
        default:
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::NotImplemented,
            "TODO: Placeholder");
          break;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}/ballots",
        HTTP_POST,
        json_adapter(json_api_version_adapter(submit_ballot)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_ballot =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}/ballots/{memberId}",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(get_ballot)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();
  }
}