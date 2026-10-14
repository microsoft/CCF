// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  static const uint32_t CCF_RUST_ABI_VERSION = 1;

  struct ccf_rust_registry;
  struct ccf_rust_endpoint_context;
  struct ccf_rust_slice
  {
    const uint8_t* data;
    size_t len;
  };

#ifdef __cplusplus
  using ccf_rust_result = int32_t;
  using ccf_rust_auth = int32_t;
  using ccf_rust_endpoint_callback =
    ccf_rust_result (*)(void* user_data, ccf_rust_endpoint_context* ctx);
  using ccf_rust_drop_callback = void (*)(void* user_data);
#else
typedef struct ccf_rust_registry ccf_rust_registry;
typedef struct ccf_rust_endpoint_context ccf_rust_endpoint_context;
typedef struct ccf_rust_slice ccf_rust_slice;
typedef int32_t ccf_rust_result;
typedef int32_t ccf_rust_auth;
typedef ccf_rust_result (*ccf_rust_endpoint_callback)(
  void* user_data, ccf_rust_endpoint_context* ctx);
typedef void (*ccf_rust_drop_callback)(void* user_data);
#endif

#ifdef __cplusplus
  inline constexpr ccf_rust_result CCF_RUST_OK = 0;
  inline constexpr ccf_rust_result CCF_RUST_NOT_FOUND = 1;
  inline constexpr ccf_rust_result CCF_RUST_INVALID_ARGUMENT = 2;
  inline constexpr ccf_rust_result CCF_RUST_READ_ONLY = 3;
  inline constexpr ccf_rust_result CCF_RUST_INTERNAL_ERROR = 4;

  inline constexpr ccf_rust_auth CCF_RUST_AUTH_NONE = 0;
  inline constexpr ccf_rust_auth CCF_RUST_AUTH_USER_CERT = 1;
#else
enum
{
  CCF_RUST_OK = 0,
  CCF_RUST_NOT_FOUND = 1,
  CCF_RUST_INVALID_ARGUMENT = 2,
  CCF_RUST_READ_ONLY = 3,
  CCF_RUST_INTERNAL_ERROR = 4
};

enum
{
  CCF_RUST_AUTH_NONE = 0,
  CCF_RUST_AUTH_USER_CERT = 1
};
#endif

  uint32_t ccf_rust_get_abi_version(void);

  ccf_rust_result ccf_rust_register_endpoint(
    ccf_rust_registry* registry,
    ccf_rust_slice path,
    ccf_rust_slice method,
    ccf_rust_auth auth,
    int32_t read_only,
    ccf_rust_endpoint_callback callback,
    ccf_rust_drop_callback drop,
    void* user_data);

  ccf_rust_result ccf_rust_request_body(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice* body);
  ccf_rust_result ccf_rust_request_query(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice* query);
  ccf_rust_result ccf_rust_request_path_param(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice name, ccf_rust_slice* value);
  ccf_rust_result ccf_rust_request_header(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice name, ccf_rust_slice* value);

  ccf_rust_result ccf_rust_response_status(
    ccf_rust_endpoint_context* ctx, uint16_t status);
  ccf_rust_result ccf_rust_response_header(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice name, ccf_rust_slice value);
  ccf_rust_result ccf_rust_response_body(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice body);
  ccf_rust_result ccf_rust_response_error(
    ccf_rust_endpoint_context* ctx,
    uint16_t status,
    ccf_rust_slice code,
    ccf_rust_slice message);

  ccf_rust_result ccf_rust_kv_get(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    ccf_rust_slice* value);
  ccf_rust_result ccf_rust_kv_has(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    int32_t* present);
  ccf_rust_result ccf_rust_kv_put(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    ccf_rust_slice value);
  ccf_rust_result ccf_rust_kv_remove(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key);

  uint32_t ccf_rust_app_abi_version(void);
  ccf_rust_result ccf_rust_app_register(ccf_rust_registry* registry);

#ifdef __cplusplus
}

namespace ccf
{
  inline constexpr uint32_t rust_abi_version = CCF_RUST_ABI_VERSION;
}
#endif
