// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "endpoint_registry.h"
#include "http/http_consts.h"
#include "http/ws_consts.h"
#include "json_handler.h"
#include "node/code_id.h"

namespace ccf
{
  /*
   * Extends the basic EndpointRegistry with methods which should be present
   * on all frontends
   */
  class CommonEndpointRegistry : public EndpointRegistry
  {
  public:
    CommonEndpointRegistry(
      const std::string& method_prefix_,
      kv::Store& store,
      const std::string& certs_table_name = "") :
      EndpointRegistry(method_prefix_, store, certs_table_name)
    {}

    void init_handlers(kv::Store& t) override
    {
      EndpointRegistry::init_handlers(t);

      auto get_commit = [this](auto&, nlohmann::json&&) {
        if (consensus != nullptr)
        {
          auto [view, seqno] = consensus->get_committed_txid();
          return make_success(GetCommit::Out{view, seqno});
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Failed to get commit info from Consensus.");
      };
      make_command_endpoint(
        "commit", HTTP_GET, json_command_adapter(get_commit), no_auth_required)
        .set_execute_locally(true)
        .set_auto_schema<void, GetCommit::Out>()
        .install();

      auto get_tx_status = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<GetTxStatus::In>();

        if (consensus != nullptr)
        {
          const auto tx_view = consensus->get_view(in.seqno);
          const auto committed_seqno = consensus->get_committed_seqno();
          const auto committed_view = consensus->get_view(committed_seqno);

          GetTxStatus::Out out;
          out.status = ccf::get_tx_status(
            in.view, in.seqno, tx_view, committed_view, committed_seqno);
          return make_success(out);
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Consensus is not yet configured.");
      };
      make_command_endpoint(
        "tx", HTTP_GET, json_command_adapter(get_tx_status), no_auth_required)
        .set_auto_schema<GetTxStatus>()
        .install();

      make_command_endpoint(
        "local_tx",
        HTTP_GET,
        json_command_adapter(get_tx_status),
        no_auth_required)
        .set_auto_schema<GetTxStatus>()
        .set_execute_locally(true)
        .install();

      auto user_id = [this](auto& args, nlohmann::json&& params) {
        GetUserId::Out out;

        if (!params.is_null())
        {
          const GetUserId::In in = params;
          auto certs_view =
            args.tx.template get_read_only_view<CertDERs>(certs_table_name);
          std::vector<uint8_t> pem(in.cert.begin(), in.cert.end());
          std::vector<uint8_t> der = tls::make_verifier(pem)->der_cert_data();
          auto caller_id_opt = certs_view->get(der);

          if (!caller_id_opt.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::UnknownCertificate,
              "Certificate not recognised.");
          }

          out.caller_id = caller_id_opt.value();
        }
        else if (
          auto user_cert_ident =
            args.template try_get_caller<ccf::UserCertAuthnIdentity>())
        {
          out.caller_id = user_cert_ident->user_id;
        }
        else if (
          auto member_cert_ident =
            args.template try_get_caller<ccf::MemberCertAuthnIdentity>())
        {
          out.caller_id = member_cert_ident->member_id;
        }
        else if (
          auto user_sig_ident =
            args.template try_get_caller<ccf::UserSignatureAuthnIdentity>())
        {
          out.caller_id = user_cert_ident->user_id;
        }
        else if (
          auto member_sig_ident =
            args.template try_get_caller<ccf::MemberSignatureAuthnIdentity>())
        {
          out.caller_id = member_cert_ident->member_id;
        }

        return make_success(out);
      };
      make_read_only_endpoint(
        "user_id",
        HTTP_GET,
        json_read_only_adapter(user_id),
        {user_cert_auth_policy,
         user_signature_auth_policy,
         member_cert_auth_policy,
         member_signature_auth_policy})
        .set_auto_schema<GetUserId::In, GetUserId::Out>()
        .install();

      auto get_code = [](auto& args, nlohmann::json&&) {
        GetCode::Out out;

        auto code_view =
          args.tx.template get_read_only_view<CodeIDs>(Tables::NODE_CODE_IDS);
        code_view->foreach(
          [&out](const ccf::CodeDigest& cd, const ccf::CodeStatus& cs) {
            auto digest = fmt::format("{:02x}", fmt::join(cd, ""));
            out.versions.push_back({digest, cs});
            return true;
          });

        return make_success(out);
      };
      make_read_only_endpoint(
        "code", HTTP_GET, json_read_only_adapter(get_code), no_auth_required)
        .set_auto_schema<void, GetCode::Out>()
        .install();

      auto openapi = [this](kv::Tx& tx, nlohmann::json&&) {
        auto document = ds::openapi::create_document(
          openapi_info.title,
          openapi_info.description,
          openapi_info.document_version);
        build_api(document, tx);
        return make_success(document);
      };
      make_endpoint("api", HTTP_GET, json_adapter(openapi), no_auth_required)
        .set_auto_schema<void, GetAPI::Out>()
        .install();

      auto endpoint_metrics_fn = [this](kv::Tx& tx, nlohmann::json&&) {
        EndpointMetrics::Out out;
        endpoint_metrics(tx, out);

        return make_success(out);
      };
      make_endpoint(
        "endpoint_metrics",
        HTTP_GET,
        json_adapter(endpoint_metrics_fn),
        no_auth_required)
        .set_auto_schema<void, EndpointMetrics::Out>()
        .install();

      auto get_receipt = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<GetReceipt::In>();

        if (history != nullptr)
        {
          try
          {
            auto p = history->get_receipt(in.commit);
            const GetReceipt::Out out{p};

            return make_success(out);
          }
          catch (const std::exception& e)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format(
                "Unable to produce receipt for commit {} : {}.",
                in.commit,
                e.what()));
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Unable to produce receipt.");
      };
      make_command_endpoint(
        "receipt",
        HTTP_GET,
        json_command_adapter(get_receipt),
        no_auth_required)
        .set_auto_schema<GetReceipt>()
        .install();

      auto verify_receipt = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<VerifyReceipt::In>();

        if (history != nullptr)
        {
          try
          {
            bool v = history->verify_receipt(in.receipt);
            const VerifyReceipt::Out out{v};

            return make_success(out);
          }
          catch (const std::exception& e)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              fmt::format("Unable to verify receipt: {}", e.what()));
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Unable to verify receipt.");
      };
      make_command_endpoint(
        "receipt/verify",
        HTTP_POST,
        json_command_adapter(verify_receipt),
        no_auth_required)
        .set_auto_schema<VerifyReceipt>()
        .install();
    }
  };
}
