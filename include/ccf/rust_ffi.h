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

  typedef struct ccf_rust_registry ccf_rust_registry;
  typedef struct ccf_rust_endpoint_context ccf_rust_endpoint_context;

  typedef struct ccf_rust_slice
  {
    const uint8_t* data;
    size_t len;
  } ccf_rust_slice;

  typedef enum ccf_rust_result
  {
    CCF_RUST_OK = 0,
    CCF_RUST_NOT_FOUND = 1,
    CCF_RUST_INVALID_ARGUMENT = 2,
    CCF_RUST_READ_ONLY = 3,
    CCF_RUST_INTERNAL_ERROR = 4
  } ccf_rust_result;

  typedef enum ccf_rust_auth
  {
    CCF_RUST_AUTH_NONE = 0,
    CCF_RUST_AUTH_USER_CERT = 1
  } ccf_rust_auth;

  typedef int (*ccf_rust_endpoint_callback)(
    void* user_data, ccf_rust_endpoint_context* ctx);
  typedef void (*ccf_rust_drop_callback)(void* user_data);

  uint32_t ccf_rust_get_abi_version(void);

  int ccf_rust_register_endpoint(
    ccf_rust_registry* registry,
    ccf_rust_slice path,
    ccf_rust_slice method,
    ccf_rust_auth auth,
    int read_only,
    ccf_rust_endpoint_callback callback,
    ccf_rust_drop_callback drop,
    void* user_data);

  int ccf_rust_request_body(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice* body);
  int ccf_rust_request_query(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice* query);
  int ccf_rust_request_path_param(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice name,
    ccf_rust_slice* value);
  int ccf_rust_request_header(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice name,
    ccf_rust_slice* value);

  int ccf_rust_response_status(ccf_rust_endpoint_context* ctx, uint16_t status);
  int ccf_rust_response_header(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice name,
    ccf_rust_slice value);
  int ccf_rust_response_body(
    ccf_rust_endpoint_context* ctx, ccf_rust_slice body);
  int ccf_rust_response_error(
    ccf_rust_endpoint_context* ctx,
    uint16_t status,
    ccf_rust_slice code,
    ccf_rust_slice message);

  int ccf_rust_kv_get(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    ccf_rust_slice* value);
  int ccf_rust_kv_has(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    int* present);
  int ccf_rust_kv_put(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key,
    ccf_rust_slice value);
  int ccf_rust_kv_remove(
    ccf_rust_endpoint_context* ctx,
    ccf_rust_slice map_name,
    ccf_rust_slice key);

  uint32_t ccf_rust_app_abi_version(void);
  int ccf_rust_app_register(ccf_rust_registry* registry);

#ifdef __cplusplus
}
#endif
