// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "request_authn_identity.h"

#include "ccf/base_endpoint_registry.h"
#include "named_auth_policies.h"
#include "template.h"

using ccf::BaseEndpointRegistry;
using ccf::endpoints::EndpointContext;

namespace ccf::v8_tmpl
{
  v8::Local<v8::Value> RequestAuthnIdentity::wrap(
    v8::Local<v8::Context> context,
    EndpointContext* endpoint_ctx,
    BaseEndpointRegistry* endpoint_registry)
  {
    v8::Isolate* isolate = context->GetIsolate();
    if (endpoint_ctx->caller == nullptr)
      return v8::Null(isolate);

    if (
      auto empty_ident =
        endpoint_ctx->try_get_caller<ccf::EmptyAuthnIdentity>())
      return RequestEmptyAuthnIdentity::wrap(context, empty_ident);
    if (auto jwt_ident = endpoint_ctx->try_get_caller<ccf::JwtAuthnIdentity>())
      return RequestJwtAuthnIdentity::wrap(context, jwt_ident);

    ReadOnlyTx* tx = &endpoint_ctx->tx;
    if (
      auto user_cert_ident =
        endpoint_ctx->try_get_caller<ccf::UserCertAuthnIdentity>())
      return RequestUserCertAuthnIdentity::wrap(
        context, user_cert_ident, endpoint_registry, tx);
    if (
      auto member_cert_ident =
        endpoint_ctx->try_get_caller<ccf::MemberCertAuthnIdentity>())
      return RequestMemberCertAuthnIdentity::wrap(
        context, member_cert_ident, endpoint_registry, tx);
    if (
      auto user_sig_ident =
        endpoint_ctx->try_get_caller<ccf::UserSignatureAuthnIdentity>())
      return RequestUserSignatureAuthnIdentity::wrap(
        context, user_sig_ident, endpoint_registry, tx);
    if (
      auto member_sig_ident =
        endpoint_ctx->try_get_caller<ccf::MemberSignatureAuthnIdentity>())
      return RequestMemberSignatureAuthnIdentity::wrap(
        context, member_sig_ident, endpoint_registry, tx);
    LOG_FATAL_FMT("Unknown caller type");
    return v8::Null(isolate);
  }

  template <typename T>
  void set_policy_name(v8::Isolate* isolate, v8::Local<v8::ObjectTemplate> tmpl)
  {
    tmpl->Set(
      isolate,
      "policy",
      v8_util::to_v8_istr(isolate, ccfapp::get_policy_name_from_ident<T>()));
  }

  v8::Local<v8::ObjectTemplate> RequestEmptyAuthnIdentity::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_policy_name<ccf::EmptyAuthnIdentity>(isolate, tmpl);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> RequestEmptyAuthnIdentity::wrap(
    v8::Local<v8::Context> context, const ccf::EmptyAuthnIdentity*)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<RequestEmptyAuthnIdentity>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    return handle_scope.Escape(result);
  }

  enum class InternalFieldJwt
  {
    Identity,
    END
  };

  static ccf::JwtAuthnIdentity* unwrap_jwt_authn_identity(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::JwtAuthnIdentity*>(
      get_internal_field(obj, InternalFieldJwt::Identity));
  }

  static void get_jwt_object(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::JwtAuthnIdentity* jwt_ident = unwrap_jwt_authn_identity(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    v8::Local<v8::Object> jwt =
      RequestJwtAuthnIdentityJwt::wrap(context, jwt_ident);

    info.GetReturnValue().Set(jwt);
  }

  v8::Local<v8::ObjectTemplate> RequestJwtAuthnIdentity::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalFieldJwt>(tmpl);

    set_policy_name<ccf::JwtAuthnIdentity>(isolate, tmpl);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "jwt"), get_jwt_object);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> RequestJwtAuthnIdentity::wrap(
    v8::Local<v8::Context> context, const ccf::JwtAuthnIdentity* identity)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<RequestJwtAuthnIdentity>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalFieldJwt>(
      result,
      {{{InternalFieldJwt::Identity, const_cast<ccf::JwtAuthnIdentity*>(identity)}}});

    return handle_scope.Escape(result);
  }

  static void get_jwt_key_issuer(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::JwtAuthnIdentity* jwt_ident = unwrap_jwt_authn_identity(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    info.GetReturnValue().Set(
      v8_util::to_v8_str(isolate, jwt_ident->key_issuer));
  }

  static void get_jwt_header(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::JwtAuthnIdentity* jwt_ident = unwrap_jwt_authn_identity(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    info.GetReturnValue().Set(v8_util::to_v8_obj(isolate, jwt_ident->header));
  }

  static void get_jwt_payload(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::JwtAuthnIdentity* jwt_ident = unwrap_jwt_authn_identity(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    info.GetReturnValue().Set(v8_util::to_v8_obj(isolate, jwt_ident->payload));
  }

  v8::Local<v8::ObjectTemplate> RequestJwtAuthnIdentityJwt::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalFieldJwt>(tmpl);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "keyIssuer"), get_jwt_key_issuer);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "header"), get_jwt_header);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "payload"), get_jwt_payload);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> RequestJwtAuthnIdentityJwt::wrap(
    v8::Local<v8::Context> context, const ccf::JwtAuthnIdentity* identity)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<RequestJwtAuthnIdentityJwt>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalFieldJwt>(
      result,
      {{{InternalFieldJwt::Identity, const_cast<ccf::JwtAuthnIdentity*>(identity)}}});

    return handle_scope.Escape(result);
  }

  enum class InternalFieldCertSig
  {
    Identity,
    EndpointRegistry,
    Tx,
    END
  };

  template <class>
  inline constexpr bool dependent_false_v = false;

  template <typename T>
  static std::string do_get_user_or_member_id(T* ident)
  {
    std::string id;
    if constexpr (
      std::is_same_v<T, ccf::UserCertAuthnIdentity> ||
      std::is_same_v<T, ccf::UserSignatureAuthnIdentity>)
      id = ident->user_id;
    else if constexpr (
      std::is_same_v<T, ccf::MemberCertAuthnIdentity> ||
      std::is_same_v<T, ccf::MemberSignatureAuthnIdentity>)
      id = ident->member_id;
    else
      static_assert(dependent_false_v<T>, "Unknown type");

    return id;
  }

  template <typename T>
  T* unwrap_authn_identity(v8::Local<v8::Object> obj)
  {
    return static_cast<T*>(
      get_internal_field(obj, InternalFieldCertSig::Identity));
  }

  static ccf::BaseEndpointRegistry* unwrap_endpoint_registry(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::BaseEndpointRegistry*>(
      get_internal_field(obj, InternalFieldCertSig::EndpointRegistry));
  }

  static ReadOnlyTx* unwrap_tx(v8::Local<v8::Object> obj)
  {
    return static_cast<ReadOnlyTx*>(
      get_internal_field(obj, InternalFieldCertSig::Tx));
  }

  template <typename T>
  static void get_user_or_member_id(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    T* ident = unwrap_authn_identity<T>(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    std::string id = do_get_user_or_member_id(ident);

    info.GetReturnValue().Set(v8_util::to_v8_str(isolate, id));
  }

  template <typename T>
  static void get_user_or_member_data(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    T* ident = unwrap_authn_identity<T>(info.Holder());
    BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());
    ReadOnlyTx* tx = unwrap_tx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    std::string id = do_get_user_or_member_id(ident);

    ccf::ApiResult result = ccf::ApiResult::OK;
    nlohmann::json data = nullptr;
    if constexpr (
      std::is_same_v<T, ccf::UserCertAuthnIdentity> ||
      std::is_same_v<T, ccf::UserSignatureAuthnIdentity>)
      result = endpoint_registry->get_user_data_v1(*tx, id, data);
    else if constexpr (
      std::is_same_v<T, ccf::MemberCertAuthnIdentity> ||
      std::is_same_v<T, ccf::MemberSignatureAuthnIdentity>)
      result = endpoint_registry->get_member_data_v1(*tx, id, data);
    else
      static_assert(dependent_false_v<T>, "Unknown type");

    if (result == ccf::ApiResult::InternalError)
    {
      isolate->ThrowError(v8_util::to_v8_str(
        isolate, fmt::format("Failed to get data for caller {}", id)));
      return;
    }

    info.GetReturnValue().Set(v8_util::to_v8_obj(isolate, data));
  }

  template <typename T>
  static void get_user_or_member_cert(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    T* ident = unwrap_authn_identity<T>(info.Holder());
    BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());
    ReadOnlyTx* tx = unwrap_tx(info.Holder());
    v8::Isolate* isolate = info.GetIsolate();

    std::string id = do_get_user_or_member_id(ident);

    ccf::ApiResult result = ccf::ApiResult::OK;
    crypto::Pem cert;
    if constexpr (
      std::is_same_v<T, ccf::UserCertAuthnIdentity> ||
      std::is_same_v<T, ccf::UserSignatureAuthnIdentity>)
      result = endpoint_registry->get_user_cert_v1(*tx, id, cert);
    else if constexpr (
      std::is_same_v<T, ccf::MemberCertAuthnIdentity> ||
      std::is_same_v<T, ccf::MemberSignatureAuthnIdentity>)
      result = endpoint_registry->get_member_cert_v1(*tx, id, cert);
    else
      static_assert(dependent_false_v<T>, "Unknown type");

    if (result == ccf::ApiResult::InternalError)
    {
      isolate->ThrowError(v8_util::to_v8_str(
        isolate, fmt::format("Failed to get certificate for caller {}", id)));
      return;
    }

    info.GetReturnValue().Set(v8_util::to_v8_str(isolate, cert.str()));
  }

  template <typename T>
  v8::Local<v8::ObjectTemplate> create_cert_or_sig_authn_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalFieldCertSig>(tmpl);

    set_policy_name<T>(isolate, tmpl);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "id"), get_user_or_member_id<T>);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "data"), get_user_or_member_data<T>);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "cert"), get_user_or_member_cert<T>);

    return handle_scope.Escape(tmpl);
  }

  template <typename T, typename U>
  v8::Local<v8::Object> wrap_cert_or_sig_authn(
    v8::Local<v8::Context> context,
    const T* identity,
    BaseEndpointRegistry* endpoint_registry,
    ReadOnlyTx* tx)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = get_cached_object_template<U>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalFieldCertSig>(
      result,
      {{{InternalFieldCertSig::Identity, const_cast<T*>(identity)},
        {InternalFieldCertSig::EndpointRegistry, endpoint_registry},
        {InternalFieldCertSig::Tx, tx}}});

    return handle_scope.Escape(result);
  }

  v8::Local<v8::ObjectTemplate> RequestUserCertAuthnIdentity::create_template(
    v8::Isolate* isolate)
  {
    return create_cert_or_sig_authn_template<ccf::UserCertAuthnIdentity>(
      isolate);
  }

  v8::Local<v8::Object> RequestUserCertAuthnIdentity::wrap(
    v8::Local<v8::Context> context,
    const ccf::UserCertAuthnIdentity* identity,
    BaseEndpointRegistry* endpoint_registry,
    ReadOnlyTx* tx)
  {
    return wrap_cert_or_sig_authn<
      ccf::UserCertAuthnIdentity,
      RequestUserCertAuthnIdentity>(context, identity, endpoint_registry, tx);
  }

  v8::Local<v8::ObjectTemplate> RequestMemberCertAuthnIdentity::create_template(
    v8::Isolate* isolate)
  {
    return create_cert_or_sig_authn_template<ccf::MemberCertAuthnIdentity>(
      isolate);
  }

  v8::Local<v8::Object> RequestMemberCertAuthnIdentity::wrap(
    v8::Local<v8::Context> context,
    const ccf::MemberCertAuthnIdentity* identity,
    BaseEndpointRegistry* endpoint_registry,
    ReadOnlyTx* tx)
  {
    return wrap_cert_or_sig_authn<
      ccf::MemberCertAuthnIdentity,
      RequestMemberCertAuthnIdentity>(context, identity, endpoint_registry, tx);
  }

  v8::Local<v8::ObjectTemplate> RequestUserSignatureAuthnIdentity::
    create_template(v8::Isolate* isolate)
  {
    return create_cert_or_sig_authn_template<ccf::UserSignatureAuthnIdentity>(
      isolate);
  }

  v8::Local<v8::Object> RequestUserSignatureAuthnIdentity::wrap(
    v8::Local<v8::Context> context,
    const ccf::UserSignatureAuthnIdentity* identity,
    BaseEndpointRegistry* endpoint_registry,
    ReadOnlyTx* tx)
  {
    return wrap_cert_or_sig_authn<
      ccf::UserSignatureAuthnIdentity,
      RequestUserSignatureAuthnIdentity>(
      context, identity, endpoint_registry, tx);
  }

  v8::Local<v8::ObjectTemplate> RequestMemberSignatureAuthnIdentity::
    create_template(v8::Isolate* isolate)
  {
    return create_cert_or_sig_authn_template<ccf::MemberSignatureAuthnIdentity>(
      isolate);
  }

  v8::Local<v8::Object> RequestMemberSignatureAuthnIdentity::wrap(
    v8::Local<v8::Context> context,
    const ccf::MemberSignatureAuthnIdentity* identity,
    BaseEndpointRegistry* endpoint_registry,
    ReadOnlyTx* tx)
  {
    return wrap_cert_or_sig_authn<
      ccf::MemberSignatureAuthnIdentity,
      RequestMemberSignatureAuthnIdentity>(
      context, identity, endpoint_registry, tx);
  }

} // namespace ccf::v8_tmpl
