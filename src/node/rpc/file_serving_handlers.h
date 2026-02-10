// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/crypto/base64.h"
#include "ccf/crypto/hash_provider.h"
#include "ccf/service/tables/nodes.h"
#include "http/http_digest.h"
#include "node/rpc/ledger_subsystem.h"
#include "snapshots/filenames.h"

namespace ccf::node
{
  // Compute and format the Repr-Digest header value for the given algorithm
  // and data.
  static std::string format_repr_digest(
    const std::string& algo_name,
    ccf::crypto::MDType md,
    const uint8_t* data,
    size_t size)
  {
    auto hp = ccf::crypto::make_hash_provider();
    auto digest = hp->Hash(data, size, md);
    auto b64 = ccf::crypto::b64_from_raw(digest.data(), digest.size());
    return fmt::format("{}=:{}:", algo_name, b64);
  }

  // Helper function to lookup redirect address based on the interface on this
  // node which received the request. Will either return an address, or
  // populate an appropriate error on the response context.
  // Takes both CommandEndpointContext and ReadOnlyTx, so that it can be
  // called be either read-only or read-write endpoints
  static std::optional<std::string> get_redirect_address_for_node(
    const ccf::endpoints::CommandEndpointContext& ctx,
    ccf::kv::ReadOnlyTx& ro_tx,
    const ccf::NodeId& target_node)
  {
    auto* nodes = ro_tx.ro<ccf::Nodes>(ccf::Tables::NODES);

    auto node_info = nodes->get(target_node);
    if (!node_info.has_value())
    {
      LOG_FAIL_FMT("Node redirection error: Unknown node {}", target_node);
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        fmt::format(
          "Cannot find node info to produce redirect response for node {}",
          target_node));
      return std::nullopt;
    }

    const auto interface_id = ctx.rpc_ctx->get_session_context()->interface_id;
    if (!interface_id.has_value())
    {
      LOG_FAIL_FMT("Node redirection error: Non-RPC request");
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        "Cannot redirect non-RPC request");
      return std::nullopt;
    }

    const auto& interfaces = node_info->rpc_interfaces;
    const auto interface_it = interfaces.find(interface_id.value());
    if (interface_it == interfaces.end())
    {
      LOG_FAIL_FMT(
        "Node redirection error: Target missing interface {}",
        interface_id.value());
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        fmt::format(
          "Cannot redirect request. Received on RPC interface {}, which is "
          "not present on target node {}",
          interface_id.value(),
          target_node));
      return std::nullopt;
    }

    const auto& interface = interface_it->second;
    return interface.published_address;
  }

  // Helper function to redirect to the next node in order after self_node_id
  // using node IDs as a sorting key, and wrapping around to the lowest ID.
  // Will either return an address, or populate an appropriate error on the
  // response context.
  static std::optional<std::string> get_redirect_address_for_next_node(
    const ccf::endpoints::CommandEndpointContext& ctx,
    ccf::kv::ReadOnlyTx& ro_tx,
    const ccf::NodeId& self_node_id)
  {
    auto* nodes = ro_tx.ro<ccf::Nodes>(ccf::Tables::NODES);
    std::set<ccf::NodeId> other_node_ids;
    nodes->foreach([&](const ccf::NodeId& node_id, const ccf::NodeInfo&) {
      if (node_id != self_node_id)
      {
        other_node_ids.insert(node_id);
      }
      return true;
    });

    if (other_node_ids.empty())
    {
      LOG_FAIL_FMT(
        "Node redirection error: No other nodes present in the network");
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        "Cannot redirect request. No other nodes present in the network");
      return std::nullopt;
    }

    auto it = other_node_ids.upper_bound(self_node_id);
    std::optional<ccf::NodeId> next_node_id;
    if (it != other_node_ids.end())
    {
      next_node_id = *it;
    }
    else
    {
      next_node_id = *other_node_ids.begin();
    }

    return get_redirect_address_for_node(ctx, ro_tx, next_node_id.value());
  }

  // Helper function to get NodeConfigurationSubsystem from NodeContext,
  // and populate error on ctx and log if not available
  static std::shared_ptr<NodeConfigurationSubsystem>
  get_node_configuration_subsystem(
    ccf::AbstractNodeContext& node_context,
    ccf::endpoints::CommandEndpointContext& ctx)
  {
    auto node_configuration_subsystem =
      node_context.get_subsystem<NodeConfigurationSubsystem>();
    if (node_configuration_subsystem == nullptr)
    {
      LOG_FAIL_FMT(
        "NodeConfigurationSubsystem is not available in NodeContext");
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        "NodeConfigurationSubsystem is not available");
    }
    return node_configuration_subsystem;
  }

  // Helper function to serve byte ranges from a file stream.
  // This populates the response body, and range-related response headers. This
  // may produce an error response if an invalid range was requested.
  //
  // If the request contains a Want-Repr-Digest header, the Repr-Digest
  // response header is set with the digest of the full file (RFC 9530),
  // regardless of any Range header.
  //
  // This DOES NOT set a response header telling the client the name of the
  // snapshot/chunk/... being served, so the caller should set this (along
  // with any other metadata headers) _before_ calling this function, and
  // generally avoid modifying the response further _after_ calling this
  // function.
  static void fill_range_response_from_file(
    ccf::endpoints::CommandEndpointContext& ctx, std::ifstream& f)
  {
    f.seekg(0, std::ifstream::end);
    const auto total_size = (size_t)f.tellg();

    ctx.rpc_ctx->set_response_header("accept-ranges", "bytes");

    // Parse Want-Repr-Digest if present
    const auto want_digest =
      ctx.rpc_ctx->get_request_header(ccf::http::headers::WANT_REPR_DIGEST);
    std::optional<std::pair<std::string, ccf::crypto::MDType>> digest_algo;
    if (want_digest.has_value())
    {
      digest_algo = ccf::http::parse_want_repr_digest(want_digest.value());
    }

    if (ctx.rpc_ctx->get_request_verb() == HTTP_HEAD)
    {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_LENGTH, total_size);

      if (digest_algo.has_value())
      {
        f.seekg(0);
        std::vector<uint8_t> full_contents(total_size);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        f.read(reinterpret_cast<char*>(full_contents.data()), total_size);

        if (f.gcount() != static_cast<std::streamsize>(total_size))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Server was unable to read the file correctly");
          return;
        }

        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::REPR_DIGEST,
          format_repr_digest(
            digest_algo->first,
            digest_algo->second,
            full_contents.data(),
            full_contents.size()));
      }
      return;
    }

    size_t range_start = 0;
    size_t range_end = total_size;
    bool has_range_header = false;
    {
      const auto range_header =
        ctx.rpc_ctx->get_request_header(ccf::http::headers::RANGE);
      if (range_header.has_value())
      {
        has_range_header = true;
        LOG_TRACE_FMT("Parsing range header {}", range_header.value());

        auto [unit, ranges] = ccf::nonstd::split_1(range_header.value(), "=");
        if (unit != "bytes")
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidHeaderValue,
            "Only 'bytes' is supported as a Range header unit");
          return;
        }

        if (ranges.find(',') != std::string::npos)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidHeaderValue,
            "Multiple ranges are not supported");
          return;
        }

        const auto segments = ccf::nonstd::split(ranges, "-");
        if (segments.size() != 2)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidHeaderValue,
            fmt::format(
              "Invalid format, cannot parse range in {}",
              range_header.value()));
          return;
        }

        const auto s_range_start = segments[0];
        const auto s_range_end = segments[1];

        if (!s_range_start.empty())
        {
          {
            const auto [p, ec] = std::from_chars(
              s_range_start.begin(), s_range_start.end(), range_start);
            if (ec != std::errc())
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidHeaderValue,
                fmt::format(
                  "Unable to parse start of range value {} in {}",
                  s_range_start,
                  range_header.value()));
              return;
            }
          }

          if (range_start > total_size)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidHeaderValue,
              fmt::format(
                "Start of range {} is larger than total file size {}",
                range_start,
                total_size));
            return;
          }

          if (!s_range_end.empty())
          {
            // Range end in header is inclusive, but we prefer to reason about
            // exclusive range end (ie - one past the end)
            size_t inclusive_range_end = 0;

            // Fully-specified range, like "X-Y"
            {
              const auto [p, ec] = std::from_chars(
                s_range_end.begin(), s_range_end.end(), inclusive_range_end);
              if (ec != std::errc())
              {
                ctx.rpc_ctx->set_error(
                  HTTP_STATUS_BAD_REQUEST,
                  ccf::errors::InvalidHeaderValue,
                  fmt::format(
                    "Unable to parse end of range value {} in {}",
                    s_range_end,
                    range_header.value()));
                return;
              }
            }

            range_end = inclusive_range_end + 1;

            if (range_end > total_size)
            {
              LOG_DEBUG_FMT(
                "Requested ledger chunk range ending at {}, but file size is "
                "only {} - shrinking range end",
                range_end,
                total_size);
              range_end = total_size;
            }

            if (range_end < range_start)
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidHeaderValue,
                fmt::format(
                  "Invalid range: Start ({}) and end ({}) out of order",
                  range_start,
                  range_end));
              return;
            }
          }
          else
          {
            // Else this is an open-ended range like "X-"
            range_end = total_size;
          }
        }
        else
        {
          if (!s_range_end.empty())
          {
            // Negative range, like "-Y"
            size_t offset = 0;
            const auto [p, ec] =
              std::from_chars(s_range_end.begin(), s_range_end.end(), offset);
            if (ec != std::errc())
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidHeaderValue,
                fmt::format(
                  "Unable to parse end of range offset value {} in {}",
                  s_range_end,
                  range_header.value()));
              return;
            }

            range_end = total_size;
            range_start = range_end - offset;
          }
          else
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidHeaderValue,
              "Invalid range: Must contain range-start or range-end");
            return;
          }
        }
      }
    }

    const auto range_size = range_end - range_start;

    LOG_TRACE_FMT(
      "Reading {}-byte range from {} to {}",
      range_size,
      range_start,
      range_end);

    // Read file contents, compute repr-digest if requested, and set
    // response body to the requested range.
    if (digest_algo.has_value())
    {
      // Need full file contents for the digest
      f.seekg(0);
      std::vector<uint8_t> full_contents(total_size);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      f.read(reinterpret_cast<char*>(full_contents.data()), total_size);
      f.close();

      auto bytes_read = static_cast<size_t>(f.gcount());
      if (bytes_read < range_end)
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Server was unable to read the file correctly");
        return;
      }

      if (bytes_read == total_size)
      {
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::REPR_DIGEST,
          format_repr_digest(
            digest_algo->first,
            digest_algo->second,
            full_contents.data(),
            full_contents.size()));
      }

      // Extract the requested range for the response body
      std::vector<uint8_t> contents(
        full_contents.begin() + range_start, full_contents.begin() + range_end);
      ctx.rpc_ctx->set_response_body(std::move(contents));
    }
    else
    {
      // Read only the requested range
      std::vector<uint8_t> contents(range_size);
      f.seekg(range_start);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      f.read(reinterpret_cast<char*>(contents.data()), contents.size());
      f.close();
      ctx.rpc_ctx->set_response_body(std::move(contents));
    }

    // Build successful response
    ctx.rpc_ctx->set_response_header(
      ccf::http::headers::CONTENT_TYPE,
      ccf::http::headervalues::contenttype::OCTET_STREAM);

    if (has_range_header)
    {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_PARTIAL_CONTENT);

      // Convert back to HTTP-style inclusive range end
      const auto inclusive_range_end = range_end - 1;

      // Partial Content responses describe the current response in
      // Content-Range
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_RANGE,
        fmt::format(
          "bytes {}-{}/{}", range_start, inclusive_range_end, total_size));
    }
    else
    {
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
    }
  }

  static void init_file_serving_handlers(
    ccf::BaseEndpointRegistry& registry, ccf::AbstractNodeContext& node_context)
  {
    static constexpr auto file_since_param_key = "since";

    auto find_snapshot = [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
      size_t latest_idx = 0;
      {
        // Get latest_idx from query param, if present
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        auto snapshot_since = http::get_query_value_opt<ccf::SeqNo>(
          parsed_query, file_since_param_key, error_reason);

        if (snapshot_since.has_value())
        {
          if (!error_reason.empty())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }
          latest_idx = snapshot_since.value();
        }
      }

      auto node_operation = node_context.get_subsystem<AbstractNodeOperation>();
      if (node_operation == nullptr)
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Unable to access NodeOperation subsystem");
        return;
      }

      if (!node_operation->can_replicate())
      {
        // Try to redirect to primary for preferable snapshot, expected to
        // match later /join request
        auto primary_id = node_operation->get_primary();
        if (primary_id.has_value())
        {
          const auto address =
            get_redirect_address_for_node(ctx, ctx.tx, *primary_id);
          if (!address.has_value())
          {
            return;
          }

          auto location =
            fmt::format("https://{}/node/snapshot", address.value());
          if (latest_idx != 0)
          {
            location += fmt::format("?{}={}", file_since_param_key, latest_idx);
          }

          ctx.rpc_ctx->set_response_header(http::headers::LOCATION, location);
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_PERMANENT_REDIRECT,
            ccf::errors::NodeCannotHandleRequest,
            "Node is not primary; redirecting for preferable snapshot");
          return;
        }

        // If there is no current primary, fall-back to returning this
        // node's best snapshot rather than terminating the fetch with an
        // error
      }

      auto node_configuration_subsystem =
        get_node_configuration_subsystem(node_context, ctx);
      if (node_configuration_subsystem == nullptr)
      {
        return;
      }

      const auto& snapshots_config =
        node_configuration_subsystem->get().node_config.snapshots;

      const auto orig_latest = latest_idx;
      auto latest_committed_snapshot =
        snapshots::find_latest_committed_snapshot_in_directory(
          snapshots_config.directory, latest_idx);

      if (!latest_committed_snapshot.has_value())
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          fmt::format(
            "This node has no committed snapshots since {}", orig_latest));
        return;
      }

      const auto& snapshot_name = latest_committed_snapshot->filename();

      const auto address =
        get_redirect_address_for_node(ctx, ctx.tx, node_context.get_node_id());
      if (!address.has_value())
      {
        return;
      }

      auto redirect_url = fmt::format(
        "https://{}/node/snapshot/{}", address.value(), snapshot_name);
      LOG_DEBUG_FMT("Redirecting to snapshot: {}", redirect_url);
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::LOCATION, redirect_url);
      ctx.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
    };
    registry
      .make_read_only_endpoint(
        "/snapshot", HTTP_HEAD, find_snapshot, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::OptionalParameter)
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();
    registry
      .make_read_only_endpoint(
        "/snapshot", HTTP_GET, find_snapshot, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::OptionalParameter)
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();

    // Find a ledger chunk that includes the since value
    auto find_chunk = [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
      size_t since_idx = 0;
      {
        // Get since_idx from query param, if present
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        auto chunk_since = http::get_query_value_opt<ccf::SeqNo>(
          parsed_query, file_since_param_key, error_reason);

        if (chunk_since.has_value())
        {
          if (!error_reason.empty())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }
          since_idx = chunk_since.value();
        }
        else
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            fmt::format(
              "Missing required query parameter '{}'", file_since_param_key));
          return;
        }
      }
      LOG_DEBUG_FMT("Finding ledger chunk including index {}", since_idx);

      auto node_operation = node_context.get_subsystem<AbstractNodeOperation>();
      if (node_operation == nullptr)
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Unable to access NodeOperation subsystem");
        return;
      }

      auto address =
        get_redirect_address_for_node(ctx, ctx.tx, node_context.get_node_id());
      if (!address.has_value())
      {
        return;
      }

      auto read_ledger_subsystem =
        node_context.get_subsystem<ccf::ReadLedgerSubsystem>();
      if (read_ledger_subsystem == nullptr)
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "LedgerReadSubsystem is not available");
        return;
      }

      const auto chunk_path =
        read_ledger_subsystem->committed_ledger_path_with_idx(since_idx);

      // If the file is found locally, always serve it from this node
      if (chunk_path.has_value())
      {
        const auto chunk_filename = chunk_path.value().filename();

        auto redirect_url = fmt::format(
          "https://{}/node/ledger-chunk/{}", address.value(), chunk_filename);
        LOG_DEBUG_FMT("Redirecting to ledger chunk: {}", redirect_url);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::LOCATION, redirect_url);
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
        return;
      }

      // Otherwise, if the file is before our init index, i.e. where we started
      // replicating, redirect to the next node in order.
      const size_t init_idx = read_ledger_subsystem->get_init_idx();
      if (since_idx < init_idx)
      {
        LOG_DEBUG_FMT(
          "This node cannot serve ledger chunk including index {} which is "
          "before its init index {} - trying to redirect to next node",
          since_idx,
          init_idx);

        address = get_redirect_address_for_next_node(
          ctx, ctx.tx, node_context.get_node_id());
        if (!address.has_value())
        {
          return;
        }

        auto location = fmt::format(
          "https://{}/node/ledger-chunk?{}={}",
          address.value(),
          file_since_param_key,
          since_idx);
        ctx.rpc_ctx->set_response_header(http::headers::LOCATION, location);
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_PERMANENT_REDIRECT,
          ccf::errors::NodeCannotHandleRequest,
          "Node does not have ledger chunk; redirecting to next node");
        return;
      }

      // If the file is beyond our init index, but we do not have it, we are
      // probably a backup and lagging behind. Redirect to primary.
      if (!node_operation->can_replicate())
      {
        LOG_DEBUG_FMT(
          "This node cannot serve ledger chunk including index {} - trying "
          "to redirect to primary",
          since_idx);
        auto primary_id = node_operation->get_primary();
        if (primary_id.has_value())
        {
          address = get_redirect_address_for_node(ctx, ctx.tx, *primary_id);
          if (address.has_value())
          {
            auto location =
              fmt::format("https://{}/node/ledger-chunk", address.value());
            location += fmt::format("?{}={}", file_since_param_key, since_idx);

            ctx.rpc_ctx->set_response_header(http::headers::LOCATION, location);
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_PERMANENT_REDIRECT,
              ccf::errors::NodeCannotHandleRequest,
              fmt::format(
                "Ledger chunk including index {} not found locally; "
                "redirecting to primary",
                since_idx));
            return;
          }
        }
      }

      // Redirect possibilities exhausted
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_NOT_FOUND,
        ccf::errors::ResourceNotFound,
        fmt::format(
          "This node has no ledger chunk including index {}", since_idx));
      return;
    };
    registry
      .make_read_only_endpoint(
        "/ledger-chunk", HTTP_HEAD, find_chunk, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::RequiredParameter)
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Ledger chunk metadata")
      .set_openapi_description(
        "Redirect to the corresponding /node/ledger-chunk/{chunk_name} "
        "endpoint for the ledger chunk including the sequence number specified "
        "in the 'since' query parameter.")
      .install();
    registry
      .make_read_only_endpoint(
        "/ledger-chunk", HTTP_GET, find_chunk, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::RequiredParameter)
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Download ledger chunk")
      .set_openapi_description(
        "Redirect to the corresponding /node/ledger-chunk/{chunk_name} "
        "endpoint for the ledger chunk including the sequence number specified "
        "in the 'since' query parameter.")
      .install();

    auto get_snapshot = [&](ccf::endpoints::CommandEndpointContext& ctx) {
      auto node_configuration_subsystem =
        get_node_configuration_subsystem(node_context, ctx);
      if (node_configuration_subsystem == nullptr)
      {
        return;
      }

      const auto& snapshots_config =
        node_configuration_subsystem->get().node_config.snapshots;

      std::string snapshot_name;
      std::string error;
      if (!ccf::endpoints::get_path_param(
            ctx.rpc_ctx->get_request_path_params(),
            "snapshot_name",
            snapshot_name,
            error))
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidResourceName,
          std::move(error));
        return;
      }

      files::fs::path snapshot_path =
        files::fs::path(snapshots_config.directory) / snapshot_name;

      std::ifstream f(snapshot_path, std::ios::binary);
      if (!f.good())
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          fmt::format(
            "This node does not have a snapshot named {}", snapshot_name));
        return;
      }

      LOG_DEBUG_FMT("Found snapshot: {}", snapshot_path.string());

      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CCF_SNAPSHOT_NAME, snapshot_name);

      fill_range_response_from_file(ctx, f);
      return;
    };
    registry
      .make_command_endpoint(
        "/snapshot/{snapshot_name}", HTTP_HEAD, get_snapshot, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();
    registry
      .make_command_endpoint(
        "/snapshot/{snapshot_name}", HTTP_GET, get_snapshot, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();

    auto get_ledger_chunk = [&](ccf::endpoints::CommandEndpointContext& ctx) {
      auto node_configuration_subsystem =
        get_node_configuration_subsystem(node_context, ctx);
      if (node_configuration_subsystem == nullptr)
      {
        return;
      }

      const auto& ledger_config =
        node_configuration_subsystem->get().node_config.ledger;

      std::string chunk_name;
      std::string error;
      if (!ccf::endpoints::get_path_param(
            ctx.rpc_ctx->get_request_path_params(),
            "chunk_name",
            chunk_name,
            error))
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidResourceName,
          std::move(error));
        return;
      }

      LOG_DEBUG_FMT("Fetching ledger chunk {}", chunk_name);

      files::fs::path chunk_path =
        files::fs::path(ledger_config.directory) / chunk_name;

      std::ifstream f(chunk_path, std::ios::binary);
      if (!f.good())
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          fmt::format(
            "This node does not have a ledger chunk named {}", chunk_name));
        return;
      }

      LOG_DEBUG_FMT("Found ledger chunk: {}", chunk_path.string());

      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CCF_LEDGER_CHUNK_NAME, chunk_name);

      fill_range_response_from_file(ctx, f);
      return;
    };
    registry
      .make_command_endpoint(
        "/ledger-chunk/{chunk_name}",
        HTTP_HEAD,
        get_ledger_chunk,
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Ledger chunk metadata")
      .set_openapi_description(
        "Metadata about a specific ledger chunk (Content-Length and "
        "x-ms-ccf-ledger-chunk-name)")
      .install();
    registry
      .make_command_endpoint(
        "/ledger-chunk/{chunk_name}",
        HTTP_GET,
        get_ledger_chunk,
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Download ledger chunk")
      .set_openapi_description(
        "Download a specific ledger chunk by name. Supports HTTP Range header "
        "for partial downloads.")
      .install();
  }
}