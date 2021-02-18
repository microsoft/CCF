// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "base_endpoint_registry.h"
#include "http/http_consts.h"
#include "http/ws_consts.h"
#include "json_handler.h"
#include "node/code_id.h"

namespace ccf
{
  /*
   * Extends the BaseEndpointRegistry by installing common endpoints we expect
   * to be available on most services. Override init_handlers or inherit from
   * BaseEndpointRegistry directly if you wish to wrap some of this
   * functionality in different Endpoints.
   */
  class CommonEndpointRegistry : public BaseEndpointRegistry
  {
  protected:
    std::string certs_table_name;

  public:
    CommonEndpointRegistry(
      const std::string& method_prefix_,
      AbstractNodeState& node_state,
      const std::string& certs_table_name_ = "") :
      BaseEndpointRegistry(method_prefix_, node_state),
      certs_table_name(certs_table_name_)
    {}

    void init_handlers() override
    {
      BaseEndpointRegistry::init_handlers();

      auto get_commit = [this](auto&, nlohmann::json&&) {
        GetCommit::Out out;
        const auto result = get_last_committed_txid_v1(out.view, out.seqno);

        if (result == ccf::ApiResult::OK)
        {
          return make_success(out);
        }
        else
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error code: {}", ccf::api_result_to_str(result)));
        }
      };
      make_command_endpoint(
        "commit", HTTP_GET, json_command_adapter(get_commit), no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, GetCommit::Out>()
        .install();

      auto get_tx_status = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<GetTxStatus::In>();

        GetTxStatus::Out out;
        const auto result =
          get_status_for_txid_v1(in.view, in.seqno, out.status);
        if (result == ccf::ApiResult::OK)
        {
          return make_success(out);
        }
        else
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error code: {}", ccf::api_result_to_str(result)));
        }
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
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto get_caller_id = [this](auto& args, nlohmann::json&& params) {
        GetCallerId::Out out;

        if (!params.is_null())
        {
          const GetCallerId::In in = params;
          auto certs = args.tx.template ro<CertDERs>(certs_table_name);
          std::vector<uint8_t> pem(in.cert.begin(), in.cert.end());
          std::vector<uint8_t> der = tls::make_verifier(pem)->cert_der();
          auto caller_id_opt = certs->get(der);

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
        "caller_id",
        HTTP_GET,
        json_read_only_adapter(get_caller_id),
        {user_cert_auth_policy,
         user_signature_auth_policy,
         member_cert_auth_policy,
         member_signature_auth_policy})
        .set_auto_schema<GetCallerId::In, GetCallerId::Out>()
        .install();

      auto get_code = [](auto& args, nlohmann::json&&) {
        GetCode::Out out;

        auto codes_ids = args.tx.template ro<CodeIDs>(Tables::NODE_CODE_IDS);
        codes_ids->foreach(
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
        nlohmann::json document;
        const auto result = generate_openapi_document_v1(
          tx,
          openapi_info.title,
          openapi_info.description,
          openapi_info.document_version,
          document);

        if (result == ccf::ApiResult::OK)
        {
          return make_success(document);
        }
        else
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error code: {}", ccf::api_result_to_str(result)));
        }
      };
      make_endpoint("api", HTTP_GET, json_adapter(openapi), no_auth_required)
        .set_auto_schema<void, GetAPI::Out>()
        .install();

      auto endpoint_metrics_fn = [this](auto&, nlohmann::json&&) {
        EndpointMetrics::Out out;
        endpoint_metrics(out);
        return make_success(out);
      };
      make_command_endpoint(
        "api/metrics",
        HTTP_GET,
        json_command_adapter(endpoint_metrics_fn),
        no_auth_required)
        .set_auto_schema<void, EndpointMetrics::Out>()
        .install();

      auto get_receipt = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<GetReceipt::In>();

        GetReceipt::Out out;
        const auto result = get_receipt_for_seqno_v1(in.commit, out.receipt);
        if (result == ccf::ApiResult::OK)
        {
          return make_success(out);
        }
        else
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error code: {}", ccf::api_result_to_str(result)));
        }
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
