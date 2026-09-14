// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/http_status.h"
#include "ccf/kv/compacted_version_conflict.h"
#include "ccf/kv/map.h"
#include "ccf/odata_error.h"
#include "ccf/rust_ffi.h"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
  using RawMap =
    ccf::kv::RawCopySerialisedMap<std::vector<uint8_t>, std::vector<uint8_t>>;
  class RustEndpointRegistry;

  bool is_valid_utf8(const ccf_rust_slice& value)
  {
    if (value.data == nullptr)
    {
      return value.len == 0;
    }

    size_t i = 0;
    while (i < value.len)
    {
      const auto first = value.data[i++];
      if (first <= 0x7f)
      {
        continue;
      }

      size_t continuation_count = 0;
      uint32_t code_point = 0;
      if ((first & 0xe0) == 0xc0)
      {
        continuation_count = 1;
        code_point = first & 0x1f;
      }
      else if ((first & 0xf0) == 0xe0)
      {
        continuation_count = 2;
        code_point = first & 0x0f;
      }
      else if ((first & 0xf8) == 0xf0)
      {
        continuation_count = 3;
        code_point = first & 0x07;
      }
      else
      {
        return false;
      }

      if (i + continuation_count > value.len)
      {
        return false;
      }

      for (size_t j = 0; j < continuation_count; ++j)
      {
        const auto next = value.data[i++];
        if ((next & 0xc0) != 0x80)
        {
          return false;
        }
        code_point = (code_point << 6) | (next & 0x3f);
      }

      const auto minimum = continuation_count == 1 ? 0x80u :
        continuation_count == 2                    ? 0x800u :
                                                     0x10000u;
      if (
        code_point < minimum || code_point > 0x10ffff ||
        (code_point >= 0xd800 && code_point <= 0xdfff))
      {
        return false;
      }
    }

    return true;
  }

  bool is_valid_buffer(const ccf_rust_slice& value)
  {
    return value.data != nullptr || value.len == 0;
  }

  bool is_http_header_name_character(uint8_t value)
  {
    if (
      (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
      (value >= 'a' && value <= 'z'))
    {
      return true;
    }

    switch (value)
    {
      case '!':
      case '#':
      case '$':
      case '%':
      case '&':
      case '\'':
      case '*':
      case '+':
      case '-':
      case '.':
      case '^':
      case '_':
      case '`':
      case '|':
      case '~':
        return true;
      default:
        return false;
    }
  }

  bool is_valid_http_header_name(const ccf_rust_slice& name)
  {
    if (name.data == nullptr || name.len == 0)
    {
      return false;
    }

    for (size_t i = 0; i < name.len; ++i)
    {
      if (!is_http_header_name_character(name.data[i]))
      {
        return false;
      }
    }
    return true;
  }

  bool is_valid_http_header_value(const ccf_rust_slice& value)
  {
    if (!is_valid_utf8(value))
    {
      return false;
    }

    for (size_t i = 0; i < value.len; ++i)
    {
      const auto byte = value.data[i];
      if ((byte < 0x20 && byte != '\t') || byte == 0x7f)
      {
        return false;
      }
    }
    return true;
  }

  bool is_known_http_status(uint16_t status)
  {
    switch (status)
    {
#define XX(code, name, string) \
  case code: \
    return true;
      HTTP_STATUS_MAP(XX)
#undef XX
      default:
        return false;
    }
  }

  std::string to_string(const ccf_rust_slice& value)
  {
    if (value.len == 0)
    {
      return {};
    }
    return {reinterpret_cast<const char*>(value.data), value.len};
  }

  RawMap::Handle::KeyType to_bytes(const ccf_rust_slice& value)
  {
    if (value.len == 0)
    {
      return {};
    }
    return {value.data, value.data + value.len};
  }

  std::vector<uint8_t> to_vector(const ccf_rust_slice& value)
  {
    if (value.len == 0)
    {
      return {};
    }
    return {value.data, value.data + value.len};
  }

  template <typename T>
  void set_slice(ccf_rust_slice* out, const T& value)
  {
    out->data = reinterpret_cast<const uint8_t*>(value.data());
    out->len = value.size();
  }

  struct CallbackState
  {
    ccf_rust_endpoint_callback callback = nullptr;
    ccf_rust_drop_callback drop = nullptr;
    void* user_data = nullptr;
    bool owns_user_data = false;

    ~CallbackState()
    {
      if (owns_user_data && drop != nullptr)
      {
        drop(user_data);
      }
    }
  };
}

struct ccf_rust_registry
{
  RustEndpointRegistry* registry;
};

struct ccf_rust_endpoint_context
{
  std::shared_ptr<ccf::RpcContext> rpc = nullptr;
  ccf::kv::ReadOnlyTx* tx = nullptr;
  ccf::kv::Tx* writable_tx = nullptr;
  std::unordered_map<std::string, RawMap::ReadOnlyHandle*> read_handles;
  std::unordered_map<std::string, RawMap::Handle*> write_handles;
  RawMap::Handle::ValueType scratch;
  std::optional<ccf::kv::CompactedVersionConflict> compacted_version_conflict =
    std::nullopt;

  RawMap::ReadOnlyHandle* read_handle(const std::string& map_name)
  {
    const auto existing = read_handles.find(map_name);
    if (existing != read_handles.end())
    {
      return existing->second;
    }

    auto* handle = tx->ro<RawMap>(map_name);
    read_handles.emplace(map_name, handle);
    return handle;
  }

  RawMap::Handle* write_handle(const std::string& map_name)
  {
    if (writable_tx == nullptr)
    {
      return nullptr;
    }

    const auto existing = write_handles.find(map_name);
    if (existing != write_handles.end())
    {
      return existing->second;
    }

    auto* handle = writable_tx->rw<RawMap>(map_name);
    write_handles.emplace(map_name, handle);
    read_handles[map_name] = handle;
    return handle;
  }

  void rethrow_compacted_version_conflict()
  {
    if (compacted_version_conflict.has_value())
    {
      throw std::move(compacted_version_conflict.value());
    }
  }
};

namespace
{
  class RustEndpointRegistry : public ccf::UserEndpointRegistry
  {
  public:
    using ccf::UserEndpointRegistry::UserEndpointRegistry;

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();
      if (ccf_rust_app_abi_version() != CCF_RUST_ABI_VERSION)
      {
        throw std::logic_error("Rust application ABI version mismatch");
      }

      ccf_rust_registry registry{this};
      if (ccf_rust_app_register(&registry) != CCF_RUST_OK)
      {
        throw std::logic_error("Rust application endpoint registration failed");
      }
    }

    void add_endpoint(
      const std::string& path,
      const ccf::RESTVerb& method,
      ccf_rust_auth auth,
      bool read_only,
      const std::shared_ptr<CallbackState>& state)
    {
      ccf::AuthnPolicies policies;
      if (auth == CCF_RUST_AUTH_USER_CERT)
      {
        policies = {ccf::user_cert_auth_policy};
      }

      if (read_only)
      {
        make_read_only_endpoint(
          path,
          method,
          [state](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
            ccf_rust_endpoint_context rust_ctx{
              ctx.rpc_ctx, &ctx.tx, nullptr, {}, {}, {}};
            try
            {
              const auto result = state->callback(state->user_data, &rust_ctx);
              rust_ctx.rethrow_compacted_version_conflict();
              if (result != CCF_RUST_OK)
              {
                ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Rust endpoint execution failed");
              }
            }
            catch (const ccf::kv::CompactedVersionConflict&)
            {
              throw;
            }
            catch (const std::exception& e)
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format("Rust endpoint bridge failed: {}", e.what()));
            }
            catch (...)
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Rust endpoint bridge failed");
            }
          },
          policies)
          .install();
      }
      else
      {
        make_endpoint(
          path,
          method,
          [state](ccf::endpoints::EndpointContext& ctx) {
            ccf_rust_endpoint_context rust_ctx{
              ctx.rpc_ctx, &ctx.tx, &ctx.tx, {}, {}, {}};
            try
            {
              const auto result = state->callback(state->user_data, &rust_ctx);
              rust_ctx.rethrow_compacted_version_conflict();
              if (result != CCF_RUST_OK)
              {
                ctx.rpc_ctx->set_error(
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Rust endpoint execution failed");
              }
            }
            catch (const ccf::kv::CompactedVersionConflict&)
            {
              throw;
            }
            catch (const std::exception& e)
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format("Rust endpoint bridge failed: {}", e.what()));
            }
            catch (...)
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Rust endpoint bridge failed");
            }
          },
          policies)
          .install();
      }
    }
  };
}

extern "C"
{
  uint32_t ccf_rust_get_abi_version(void)
  {
    return CCF_RUST_ABI_VERSION;
  }

  ccf_rust_result ccf_rust_register_endpoint(
    ccf_rust_registry* registry,
    ccf_rust_slice path,
    ccf_rust_slice method,
    ccf_rust_auth auth,
    int32_t read_only,
    ccf_rust_endpoint_callback callback,
    ccf_rust_drop_callback drop,
    void* user_data)
  {
    if (
      registry == nullptr || registry->registry == nullptr ||
      !is_valid_utf8(path) || path.len == 0 || !is_valid_utf8(method) ||
      method.len == 0 || callback == nullptr ||
      (auth != CCF_RUST_AUTH_NONE && auth != CCF_RUST_AUTH_USER_CERT) ||
      (read_only != 0 && read_only != 1))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }

    try
    {
      auto state = std::make_shared<CallbackState>(callback, drop, user_data);
      registry->registry->add_endpoint(
        to_string(path),
        ccf::RESTVerb(to_string(method)),
        auth,
        read_only == 1,
        state);
      state->owns_user_data = true;
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_request_body(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice* body)
  {
    if (ctx == nullptr || body == nullptr)
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      set_slice(body, ctx->rpc->get_request_body());
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_request_query(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice* query)
  {
    if (ctx == nullptr || query == nullptr)
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      set_slice(query, ctx->rpc->get_request_query());
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_request_path_param(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice name, ccf_rust_slice* value)
  {
    if (ctx == nullptr || value == nullptr || !is_valid_utf8(name))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      const auto& params = ctx->rpc->get_decoded_request_path_params();
      const auto it = params.find(to_string(name));
      if (it == params.end())
      {
        return CCF_RUST_NOT_FOUND;
      }
      ctx->scratch.clear();
      ctx->scratch.insert(
        ctx->scratch.end(), it->second.begin(), it->second.end());
      set_slice(value, ctx->scratch);
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_request_header(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice name, ccf_rust_slice* value)
  {
    if (ctx == nullptr || value == nullptr || !is_valid_utf8(name))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      const auto header = ctx->rpc->get_request_header(to_string(name));
      if (!header.has_value())
      {
        return CCF_RUST_NOT_FOUND;
      }
      ctx->scratch.clear();
      ctx->scratch.insert(ctx->scratch.end(), header->begin(), header->end());
      set_slice(value, ctx->scratch);
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_response_status(
    ccf_rust_endpoint_context* ctx, uint16_t status)
  {
    if (ctx == nullptr || !is_known_http_status(status))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      ctx->rpc->set_response_status(status);
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_response_header(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice name, ccf_rust_slice value)
  {
    if (
      ctx == nullptr || !is_valid_http_header_name(name) ||
      !is_valid_http_header_value(value))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      ctx->rpc->set_response_header(to_string(name), to_string(value));
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_response_body(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice body)
  {
    if (ctx == nullptr || !is_valid_buffer(body))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      ctx->rpc->set_response_body(to_vector(body));
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_response_error(
    ccf_rust_endpoint_context* ctx,
    uint16_t status,
    ccf_rust_slice code,
    ccf_rust_slice message)
  {
    if (
      ctx == nullptr || status < 400 || !is_known_http_status(status) ||
      !is_valid_utf8(code) || code.len == 0 || !is_valid_utf8(message))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      ctx->rpc->set_error(
        static_cast<ccf::http_status>(status),
        to_string(code),
        to_string(message));
      return CCF_RUST_OK;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_kv_get(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    ccf_rust_slice* value)
  {
    if (
      ctx == nullptr || value == nullptr || !is_valid_utf8(map_name) ||
      map_name.len == 0 || !is_valid_buffer(key))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      auto result = ctx->read_handle(to_string(map_name))->get(to_bytes(key));
      if (!result.has_value())
      {
        return CCF_RUST_NOT_FOUND;
      }
      ctx->scratch = std::move(result.value());
      set_slice(value, ctx->scratch);
      return CCF_RUST_OK;
    }
    catch (const ccf::kv::CompactedVersionConflict& e)
    {
      ctx->compacted_version_conflict = e;
      return CCF_RUST_INTERNAL_ERROR;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_kv_has(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    int32_t* present)
  {
    if (
      ctx == nullptr || present == nullptr || !is_valid_utf8(map_name) ||
      map_name.len == 0 || !is_valid_buffer(key))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      *present =
        ctx->read_handle(to_string(map_name))->has(to_bytes(key)) ? 1 : 0;
      return CCF_RUST_OK;
    }
    catch (const ccf::kv::CompactedVersionConflict& e)
    {
      ctx->compacted_version_conflict = e;
      return CCF_RUST_INTERNAL_ERROR;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_kv_put(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    ccf_rust_slice value)
  {
    if (
      ctx == nullptr || !is_valid_utf8(map_name) || map_name.len == 0 ||
      !is_valid_buffer(key) || !is_valid_buffer(value))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      auto* handle = ctx->write_handle(to_string(map_name));
      if (handle == nullptr)
      {
        return CCF_RUST_READ_ONLY;
      }
      handle->put(to_bytes(key), to_bytes(value));
      return CCF_RUST_OK;
    }
    catch (const ccf::kv::CompactedVersionConflict& e)
    {
      ctx->compacted_version_conflict = e;
      return CCF_RUST_INTERNAL_ERROR;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }

  ccf_rust_result ccf_rust_kv_remove(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice map_name, ccf_rust_slice key)
  {
    if (
      ctx == nullptr || !is_valid_utf8(map_name) || map_name.len == 0 ||
      !is_valid_buffer(key))
    {
      return CCF_RUST_INVALID_ARGUMENT;
    }
    try
    {
      auto* handle = ctx->write_handle(to_string(map_name));
      if (handle == nullptr)
      {
        return CCF_RUST_READ_ONLY;
      }
      handle->remove(to_bytes(key));
      return CCF_RUST_OK;
    }
    catch (const ccf::kv::CompactedVersionConflict& e)
    {
      ctx->compacted_version_conflict = e;
      return CCF_RUST_INTERNAL_ERROR;
    }
    catch (...)
    {
      return CCF_RUST_INTERNAL_ERROR;
    }
  }
}

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<RustEndpointRegistry>(context);
  }
}
