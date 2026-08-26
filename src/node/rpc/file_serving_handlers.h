// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/crypto/base64.h"
#include "ccf/crypto/hash_provider.h"
#include "ccf/http_etag.h"
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
    auto digest = hp->hash(data, size, md);
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

  // Helper function to serve byte ranges from a resource.
  // This populates the response body, and range-related response headers. This
  // may produce an error response if an invalid range was requested.
  //
  // If the request contains a Want-Repr-Digest header, the Repr-Digest
  // response header is set with the digest of the full file (RFC 9530),
  // regardless of any Range header.
  //
  // An ETag header is always set on successful responses, containing a
  // SHA-256 digest of the response content in RFC 9530 structured field
  // format. If an If-None-Match request header is present and matches
  // the ETag, a 304 Not Modified response is returned instead. This
  // applies to both GET and HEAD requests.
  //
  // This DOES NOT set a response header telling the client the name of the
  // snapshot/chunk/... being served, so the caller should set this (along
  // with any other metadata headers) _before_ calling this function, and
  // generally avoid modifying the response further _after_ calling this
  // function.
  template <typename ReadRange>
  // NOLINTNEXTLINE(readability-function-cognitive-complexity)
  static void fill_range_response(
    ccf::endpoints::CommandEndpointContext& ctx,
    size_t total_size,
    ReadRange&& read_range)
  {
    if (total_size == 0)
    {
      // Refuse to return an empty file - it's not going to be a valid snapshot
      // or ledger chunk, and cannot be described in a Content-Range response
      // header
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::EmptyFile,
        "Found empty file");
      return;
    }

    const bool is_head = ctx.rpc_ctx->get_request_verb() == HTTP_HEAD;

    ctx.rpc_ctx->set_response_header("accept-ranges", "bytes");

    // Parse Want-Repr-Digest if present
    const auto want_digest =
      ctx.rpc_ctx->get_request_header(ccf::http::headers::WANT_REPR_DIGEST);
    std::optional<std::pair<std::string, ccf::crypto::MDType>> digest_algo;
    if (want_digest.has_value())
    {
      digest_algo = ccf::http::parse_want_repr_digest(want_digest.value());
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
            range_start = offset >= range_end ? 0 : range_end - offset;
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

    // Read file contents. We need the range content for the response body
    // (GET) or to compute ETag/Repr-Digest (both GET and HEAD).
    // If Repr-Digest is requested, read the full file; otherwise read
    // only the requested range.
    std::vector<uint8_t> contents;
    if (digest_algo.has_value())
    {
      auto full_contents = read_range(0, total_size);
      if (!full_contents.has_value() || full_contents->size() != total_size)
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
          full_contents->data(),
          full_contents->size()));

      // Extract the requested range
      if (range_start == 0 && range_end == total_size)
      {
        contents = std::move(full_contents.value());
      }
      else
      {
        contents.assign(
          full_contents->begin() + range_start,
          full_contents->begin() + range_end);
      }
    }
    else
    {
      auto range_contents = read_range(range_start, range_end);
      if (!range_contents.has_value() || range_contents->size() != range_size)
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Server was unable to read the file correctly");
        return;
      }
      contents = std::move(range_contents.value());
    }

    // Compute ETag over the response content (RFC 9530 structured field
    // format)
    auto hash_provider = ccf::crypto::make_hash_provider();
    auto sha256_hash = hash_provider->hash(
      contents.data(), contents.size(), ccf::crypto::MDType::SHA256);
    auto sha256_b64 =
      ccf::crypto::b64_from_raw(sha256_hash.data(), sha256_hash.size());
    auto sha256_etag = fmt::format("sha-256=:{}:", sha256_b64);

    ctx.rpc_ctx->set_response_header(
      ccf::http::headers::ETAG, fmt::format("\"{}\"", sha256_etag));

    // Check If-None-Match header
    const auto if_none_match =
      ctx.rpc_ctx->get_request_header(ccf::http::headers::IF_NONE_MATCH);
    if (if_none_match.has_value())
    {
      try
      {
        ccf::http::Matcher matcher(if_none_match.value());

        bool matched = matcher.is_any() || matcher.matches(sha256_etag);

        if (!matched)
        {
          auto sha384_hash = hash_provider->hash(
            contents.data(), contents.size(), ccf::crypto::MDType::SHA384);
          auto sha384_b64 =
            ccf::crypto::b64_from_raw(sha384_hash.data(), sha384_hash.size());
          matched = matcher.matches(fmt::format("sha-384=:{}:", sha384_b64));
        }

        if (!matched)
        {
          auto sha512_hash = hash_provider->hash(
            contents.data(), contents.size(), ccf::crypto::MDType::SHA512);
          auto sha512_b64 =
            ccf::crypto::b64_from_raw(sha512_hash.data(), sha512_hash.size());
          matched = matcher.matches(fmt::format("sha-512=:{}:", sha512_b64));
        }

        if (matched)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_NOT_MODIFIED);
          ctx.rpc_ctx->set_response_body(std::vector<uint8_t>{});
          return;
        }
      }
      catch (const ccf::http::MatcherError& e)
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidHeaderValue, e.what());
        return;
      }
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

    if (is_head)
    {
      // HEAD responses should not include a body, but should include
      // Content-Length indicating the size of the resource
      ctx.rpc_ctx->set_response_header(
        ccf::http::headers::CONTENT_LENGTH,
        has_range_header ? range_size : total_size);
    }
    else
    {
      ctx.rpc_ctx->set_response_body(std::move(contents));
    }
  }

  static void fill_range_response_from_file(
    ccf::endpoints::CommandEndpointContext& ctx, std::ifstream& f)
  {
    f.seekg(0, std::ifstream::end);
    const auto end = f.tellg();
    if (end < 0)
    {
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_INTERNAL_SERVER_ERROR,
        ccf::errors::InternalError,
        "Server was unable to determine the file size");
      return;
    }

    const auto total_size = static_cast<size_t>(end);
    const auto read_range =
      [&f](size_t start, size_t end) -> std::optional<std::vector<uint8_t>> {
      const auto size = end - start;
      std::vector<uint8_t> contents(size);
      f.clear();
      f.seekg(static_cast<std::streamoff>(start), std::ifstream::beg);
      if (!f.good())
      {
        return std::nullopt;
      }

      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      f.read(reinterpret_cast<char*>(contents.data()), contents.size());
      if (static_cast<size_t>(f.gcount()) != size)
      {
        return std::nullopt;
      }
      return contents;
    };

    fill_range_response(ctx, total_size, read_range);
  }

  static void fill_range_response_from_contents(
    ccf::endpoints::CommandEndpointContext& ctx, std::vector<uint8_t>&& source)
  {
    const auto total_size = source.size();
    const auto read_range =
      [&source](
        size_t start, size_t end) -> std::optional<std::vector<uint8_t>> {
      if (start > end || end > source.size())
      {
        return std::nullopt;
      }

      if (start == 0 && end == source.size())
      {
        return std::move(source);
      }

      return std::vector<uint8_t>(source.begin() + start, source.begin() + end);
    };

    fill_range_response(ctx, total_size, read_range);
  }

  // NOLINTNEXTLINE(readability-function-cognitive-complexity)
  static void init_file_serving_handlers(
    ccf::BaseEndpointRegistry& registry, ccf::AbstractNodeContext& node_context)
  {
    static constexpr auto file_since_param_key = "since";
    static constexpr auto include_committed_prefix_param_key =
      "include_committed_prefix";

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
      .add_openapi_response(
        HTTP_STATUS_PERMANENT_REDIRECT, "Redirect to the selected snapshot.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "No matching snapshot is available.")
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();
    registry
      .make_read_only_endpoint(
        "/snapshot", HTTP_GET, find_snapshot, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::OptionalParameter)
      .add_openapi_response(
        HTTP_STATUS_PERMANENT_REDIRECT, "Redirect to the selected snapshot.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "No matching snapshot is available.")
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();

    // Find a ledger chunk that includes the since value
    auto find_chunk = [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
      size_t since_idx = 0;
      bool include_committed_prefix = false;
      {
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

        if (parsed_query.contains(include_committed_prefix_param_key))
        {
          error_reason.clear();
          if (!http::get_query_value(
                parsed_query,
                include_committed_prefix_param_key,
                include_committed_prefix,
                error_reason))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }
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

      const auto redirect_to_committed_chunk =
        [&](const std::filesystem::path& path) {
          const auto chunk_filename = path.filename();
          const auto redirect_url = fmt::format(
            "https://{}/node/ledger_chunk/{}", address.value(), chunk_filename);
          LOG_DEBUG_FMT("Redirecting to ledger chunk: {}", redirect_url);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::LOCATION, redirect_url);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
        };

      // If the file is found locally, always serve it from this node
      if (chunk_path.has_value())
      {
        redirect_to_committed_chunk(chunk_path.value());
        return;
      }

      if (include_committed_prefix)
      {
        const auto prefix_range =
          read_ledger_subsystem->committed_ledger_prefix_range_with_idx(
            since_idx);
        if (prefix_range.has_value())
        {
          const auto chunk_filename = fmt::format(
            "ledger_{}-{}{}",
            prefix_range->start_idx,
            prefix_range->end_idx,
            asynchost::ledger_committed_prefix_suffix);
          const auto redirect_url = fmt::format(
            "https://{}/node/ledger_chunk/committed_prefix/{}",
            address.value(),
            chunk_filename);
          LOG_DEBUG_FMT(
            "Redirecting to committed ledger prefix: {}", redirect_url);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::LOCATION, redirect_url);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CACHE_CONTROL, "no-store");
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_TEMPORARY_REDIRECT);
          return;
        }

        // A completed source file may have been promoted after the first
        // committed-file lookup but before the prefix lookup. Retry the
        // canonical lookup so this atomic state transition cannot produce a
        // false 404.
        const auto promoted_chunk_path =
          read_ledger_subsystem->committed_ledger_path_with_idx(since_idx);
        if (promoted_chunk_path.has_value())
        {
          redirect_to_committed_chunk(promoted_chunk_path.value());
          return;
        }
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
          "https://{}/node/ledger_chunk?{}={}",
          address.value(),
          file_since_param_key,
          since_idx);
        if (include_committed_prefix)
        {
          location +=
            fmt::format("&{}=true", include_committed_prefix_param_key);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CACHE_CONTROL, "no-store");
        }
        ctx.rpc_ctx->set_response_header(http::headers::LOCATION, location);
        ctx.rpc_ctx->set_error(
          include_committed_prefix ? HTTP_STATUS_TEMPORARY_REDIRECT :
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
              fmt::format("https://{}/node/ledger_chunk", address.value());
            location += fmt::format("?{}={}", file_since_param_key, since_idx);
            if (include_committed_prefix)
            {
              location +=
                fmt::format("&{}=true", include_committed_prefix_param_key);
              ctx.rpc_ctx->set_response_header(
                ccf::http::headers::CACHE_CONTROL, "no-store");
            }

            ctx.rpc_ctx->set_response_header(http::headers::LOCATION, location);
            ctx.rpc_ctx->set_error(
              include_committed_prefix ? HTTP_STATUS_TEMPORARY_REDIRECT :
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
      if (include_committed_prefix)
      {
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CACHE_CONTROL, "no-store");
      }
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_NOT_FOUND,
        ccf::errors::ResourceNotFound,
        fmt::format(
          "This node has no ledger chunk including index {}", since_idx));
      return;
    };
    registry
      .make_read_only_endpoint(
        "/ledger_chunk", HTTP_HEAD, find_chunk, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::RequiredParameter)
      .add_query_parameter<bool>(
        include_committed_prefix_param_key, ccf::endpoints::OptionalParameter)
      .add_openapi_response(
        HTTP_STATUS_TEMPORARY_REDIRECT,
        "Redirect to a temporary committed ledger prefix.")
      .add_openapi_response(
        HTTP_STATUS_PERMANENT_REDIRECT,
        "Redirect to the selected ledger chunk.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "No matching ledger chunk is available.")
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Ledger chunk metadata")
      .set_openapi_description(
        "Redirect to the corresponding /node/ledger_chunk/{chunk_name} "
        "endpoint for the ledger chunk including the sequence number specified "
        "in the 'since' query parameter. If 'include_committed_prefix' is true "
        "and no committed file is available, this may temporarily redirect to "
        "a synthetic committed-prefix resource.")
      .install();
    registry
      .make_read_only_endpoint(
        "/ledger_chunk", HTTP_GET, find_chunk, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_query_parameter<ccf::SeqNo>(
        file_since_param_key, ccf::endpoints::RequiredParameter)
      .add_query_parameter<bool>(
        include_committed_prefix_param_key, ccf::endpoints::OptionalParameter)
      .add_openapi_response(
        HTTP_STATUS_TEMPORARY_REDIRECT,
        "Redirect to a temporary committed ledger prefix.")
      .add_openapi_response(
        HTTP_STATUS_PERMANENT_REDIRECT,
        "Redirect to the selected ledger chunk.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "No matching ledger chunk is available.")
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Download ledger chunk")
      .set_openapi_description(
        "Redirect to the corresponding /node/ledger_chunk/{chunk_name} "
        "endpoint for the ledger chunk including the sequence number specified "
        "in the 'since' query parameter. If 'include_committed_prefix' is true "
        "and no committed file is available, this may temporarily redirect to "
        "a synthetic committed-prefix resource.")
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
      .add_openapi_response(
        HTTP_STATUS_OK, "Metadata for the requested snapshot.")
      .add_openapi_response(
        HTTP_STATUS_PARTIAL_CONTENT,
        "Metadata for the requested snapshot range.")
      .add_openapi_response(
        HTTP_STATUS_NOT_MODIFIED, "The requested snapshot has not changed.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "The requested snapshot is not available.")
      .require_operator_feature(endpoints::OperatorFeature::SnapshotRead)
      .install();
    registry
      .make_command_endpoint(
        "/snapshot/{snapshot_name}", HTTP_GET, get_snapshot, no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_openapi_response<ds::openapi::Binary>(
        HTTP_STATUS_OK, "The requested snapshot.")
      .add_openapi_response<ds::openapi::Binary>(
        HTTP_STATUS_PARTIAL_CONTENT,
        "The requested byte range of the snapshot.")
      .add_openapi_response(
        HTTP_STATUS_NOT_MODIFIED, "The requested snapshot has not changed.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "The requested snapshot is not available.")
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
        "/ledger_chunk/{chunk_name}",
        HTTP_HEAD,
        get_ledger_chunk,
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_openapi_response(
        HTTP_STATUS_OK, "Metadata for the requested ledger chunk.")
      .add_openapi_response(
        HTTP_STATUS_PARTIAL_CONTENT,
        "Metadata for the requested ledger chunk range.")
      .add_openapi_response(
        HTTP_STATUS_NOT_MODIFIED, "The requested ledger chunk has not changed.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "The requested ledger chunk is not available.")
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Ledger chunk metadata")
      .set_openapi_description(
        "Metadata about a specific ledger chunk (Content-Length and "
        "x-ms-ccf-ledger-chunk-name)")
      .install();
    registry
      .make_command_endpoint(
        "/ledger_chunk/{chunk_name}",
        HTTP_GET,
        get_ledger_chunk,
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_openapi_response<ds::openapi::Binary>(
        HTTP_STATUS_OK, "The requested ledger chunk.")
      .add_openapi_response<ds::openapi::Binary>(
        HTTP_STATUS_PARTIAL_CONTENT,
        "The requested byte range of the ledger chunk.")
      .add_openapi_response(
        HTTP_STATUS_NOT_MODIFIED, "The requested ledger chunk has not changed.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND, "The requested ledger chunk is not available.")
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Download ledger chunk")
      .set_openapi_description(
        "Download a specific ledger chunk by name. Supports HTTP Range header "
        "for partial downloads.")
      .install();

    auto get_committed_ledger_prefix =
      [&](ccf::endpoints::CommandEndpointContext& ctx) {
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CACHE_CONTROL, "no-store");

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

        const auto range =
          asynchost::get_ledger_committed_prefix_range_from_file_name(
            chunk_name);
        if (!range.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidResourceName,
            fmt::format(
              "{} is not a valid committed ledger prefix name", chunk_name));
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

        auto contents = read_ledger_subsystem->read_committed_ledger_prefix(
          range->first, range->second);
        if (!contents.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "This node cannot provide committed ledger prefix {}",
              chunk_name));
          return;
        }

        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CCF_LEDGER_CHUNK_NAME, chunk_name);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CCF_LEDGER_CHUNK_KIND, "committed-prefix");
        fill_range_response_from_contents(ctx, std::move(contents.value()));
      };
    registry
      .make_command_endpoint(
        "/ledger_chunk/committed_prefix/{chunk_name}",
        HTTP_HEAD,
        get_committed_ledger_prefix,
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_openapi_response(
        HTTP_STATUS_OK, "Metadata for the requested committed ledger prefix.")
      .add_openapi_response(
        HTTP_STATUS_PARTIAL_CONTENT,
        "Metadata for the requested committed ledger prefix range.")
      .add_openapi_response(
        HTTP_STATUS_NOT_MODIFIED,
        "The requested committed ledger prefix has not changed.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND,
        "The requested committed ledger prefix is not available.")
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Committed ledger prefix metadata")
      .set_openapi_description(
        "Metadata about a synthetic chunk containing only committed ledger "
        "entries. The resource is not a canonical .committed ledger file.")
      .install();
    registry
      .make_command_endpoint(
        "/ledger_chunk/committed_prefix/{chunk_name}",
        HTTP_GET,
        get_committed_ledger_prefix,
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .add_openapi_response<ds::openapi::Binary>(
        HTTP_STATUS_OK, "The requested committed ledger prefix.")
      .add_openapi_response<ds::openapi::Binary>(
        HTTP_STATUS_PARTIAL_CONTENT,
        "The requested byte range of the committed ledger prefix.")
      .add_openapi_response(
        HTTP_STATUS_NOT_MODIFIED,
        "The requested committed ledger prefix has not changed.")
      .add_openapi_response(
        HTTP_STATUS_NOT_FOUND,
        "The requested committed ledger prefix is not available.")
      .require_operator_feature(endpoints::OperatorFeature::LedgerChunkRead)
      .set_openapi_summary("Download committed ledger prefix")
      .set_openapi_description(
        "Download a synthetic chunk containing only committed ledger entries. "
        "Supports HTTP Range and digest headers. The resource is not a "
        "canonical .committed ledger file and must not be used for recovery.")
      .install();
  }
}