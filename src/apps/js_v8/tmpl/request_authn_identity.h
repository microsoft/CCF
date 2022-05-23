// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/endpoint_context.h"
#include "ccf/endpoints/authentication/cert_auth.h"
#include "ccf/endpoints/authentication/empty_auth.h"
#include "ccf/endpoints/authentication/jwt_auth.h"
#include "ccf/endpoints/authentication/sig_auth.h"
#include "ccf/tx.h"

#include <v8.h>

using ccf::BaseEndpointRegistry;
using ccf::endpoints::EndpointContext;
using kv::ReadOnlyTx;

namespace ccf::v8_tmpl
{
  // Not a real template, forwards to the concrete templates below.
  class RequestAuthnIdentity
  {
  public:
    static v8::Local<v8::Value> wrap(
      v8::Local<v8::Context> context,
      EndpointContext* endpoint_ctx,
      BaseEndpointRegistry* endpoint_registry);
  };

  class RequestEmptyAuthnIdentity
  {
  public:
    static constexpr const char* NAME = "CCFRequestEmptyAuthnIdentity";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, const ccf::EmptyAuthnIdentity* identity);
  };

  class RequestJwtAuthnIdentity
  {
  public:
    static constexpr const char* NAME = "CCFRequestJwtAuthnIdentity";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, const ccf::JwtAuthnIdentity* identity);
  };

  class RequestJwtAuthnIdentityJwt
  {
  public:
    static constexpr const char* NAME = "CCFRequestJwtAuthnIdentityJwt";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, const ccf::JwtAuthnIdentity* identity);
  };

  class RequestUserCertAuthnIdentity
  {
  public:
    static constexpr const char* NAME = "CCFRequestUserCertAuthnIdentity";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      const ccf::UserCertAuthnIdentity* identity,
      BaseEndpointRegistry* endpoint_registry,
      ReadOnlyTx* tx);
  };

  class RequestMemberCertAuthnIdentity
  {
  public:
    static constexpr const char* NAME = "CCFRequestMemberCertAuthnIdentity";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      const ccf::MemberCertAuthnIdentity* identity,
      BaseEndpointRegistry* endpoint_registry,
      ReadOnlyTx* tx);
  };

  class RequestUserSignatureAuthnIdentity
  {
  public:
    static constexpr const char* NAME = "CCFRequestUserSignatureAuthnIdentity";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      const ccf::UserSignatureAuthnIdentity* identity,
      BaseEndpointRegistry* endpoint_registry,
      ReadOnlyTx* tx);
  };

  class RequestMemberSignatureAuthnIdentity
  {
  public:
    static constexpr const char* NAME =
      "CCFRequestMemberSignatureAuthnIdentity";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      const ccf::MemberSignatureAuthnIdentity* identity,
      BaseEndpointRegistry* endpoint_registry,
      ReadOnlyTx* tx);
  };

} // namespace ccf::v8_tmpl
