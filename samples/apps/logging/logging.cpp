// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "formatters.h"
#include "logging_schema.h"
#include "node/quote.h"
#include "node/rpc/user_frontend.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace std;
using namespace nlohmann;

namespace loggingapp
{
  // SNIPPET: table_definition
  using Table = kv::Map<size_t, string>;

  // SNIPPET: inherit_frontend
  class LoggerHandlers : public ccf::UserEndpointRegistry
  {
  private:
    Table records;
    Table public_records;

    const nlohmann::json record_public_params_schema;
    const nlohmann::json record_public_result_schema;

    const nlohmann::json get_public_params_schema;
    const nlohmann::json get_public_result_schema;

  public:
    // SNIPPET_START: constructor
    LoggerHandlers(
      ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(nwt),
      records("records"),
      public_records("public:records"),
      // SNIPPET_END: constructor
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      const ccf::endpoints::AuthnPolicies user_cert_required = {
        ccf::user_cert_auth_policy};

      // SNIPPET_START: record
      auto record = [this](kv::Tx& tx, nlohmann::json&& params) {
        // SNIPPET_START: macro_validation_record
        const auto in = params.get<LoggingRecord::In>();
        // SNIPPET_END: macro_validation_record

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto view = tx.get_view(records);
        view->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: install_record
      make_endpoint(
        "log/private", HTTP_POST, ccf::json_adapter(record), user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_record

      make_endpoint(
        "log/private",
        ws::Verb::WEBSOCKET,
        ccf::json_adapter(record),
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get
      auto get =
        [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingGet::In>();
          auto view = args.tx.get_read_only_view(records);
          auto r = view->get(in.id);

          if (r.has_value())
            return ccf::make_success(LoggingGet::Out{r.value()});

          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ResourceNotFound,
            fmt::format("No such record: {}.", in.id));
        };
      // SNIPPET_END: get

      // SNIPPET_START: install_get
      make_read_only_endpoint(
        "log/private",
        HTTP_GET,
        ccf::json_read_only_adapter(get),
        user_cert_required)
        .set_auto_schema<LoggingGet>()
        .install();
      // SNIPPET_END: install_get

      auto remove = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRemove::In>();
        auto view = tx.get_view(records);
        auto removed = view->remove(in.id);

        return ccf::make_success(LoggingRemove::Out{removed});
      };
      make_endpoint(
        "log/private",
        HTTP_DELETE,
        ccf::json_adapter(remove),
        user_cert_required)
        .set_auto_schema<LoggingRemove>()
        .install();

      // SNIPPET_START: record_public
      auto record_public = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto view = tx.get_view(public_records);
        view->put(params["id"], in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record_public
      make_endpoint(
        "log/public",
        HTTP_POST,
        ccf::json_adapter(record_public),
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get_public
      auto get_public =
        [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingGet::In>();
          auto view = args.tx.get_read_only_view(public_records);
          auto r = view->get(in.id);

          if (r.has_value())
            return ccf::make_success(LoggingGet::Out{r.value()});

          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ResourceNotFound,
            fmt::format("No such record: {}.", in.id));
        };
      // SNIPPET_END: get_public
      make_read_only_endpoint(
        "log/public",
        HTTP_GET,
        ccf::json_read_only_adapter(get_public),
        user_cert_required)
        .set_auto_schema<LoggingGet>()
        .install();

      auto remove_public = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRemove::In>();
        auto view = tx.get_view(public_records);
        auto removed = view->remove(in.id);

        return ccf::make_success(LoggingRemove::Out{removed});
      };
      make_endpoint(
        "log/public",
        HTTP_DELETE,
        ccf::json_adapter(remove_public),
        user_cert_required)
        .set_auto_schema<LoggingRemove>()
        .install();

      // SNIPPET_START: log_record_prefix_cert
      auto log_record_prefix_cert = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());

        const auto in = body_j.get<LoggingRecord::In>();
        if (in.msg.empty())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body("Cannot record an empty log message");
          return;
        }

        auto cert = mbedtls::make_unique<mbedtls::X509Crt>();

        const auto& cert_data = args.rpc_ctx->session->caller_cert;
        const auto ret = mbedtls_x509_crt_parse(
          cert.get(), cert_data.data(), cert_data.size());
        if (ret != 0)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            "Cannot parse x509 caller certificate");
          return;
        }

        const auto log_line = fmt::format("{}: {}", cert->subject, in.msg);
        auto view = args.tx.get_view(records);
        view->put(in.id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(true).dump());
      };
      make_endpoint(
        "log/private/prefix_cert",
        HTTP_POST,
        log_record_prefix_cert,
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: log_record_prefix_cert

      auto log_record_anonymous =
        [this](ccf::EndpointContext& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingRecord::In>();
          if (in.msg.empty())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "Cannot record an empty log message.");
          }

          const auto log_line = fmt::format("Anonymous: {}", in.msg);
          auto view = args.tx.get_view(records);
          view->put(in.id, log_line);
          return ccf::make_success(true);
        };
      make_endpoint(
        "log/private/anonymous",
        HTTP_POST,
        ccf::json_adapter(log_record_anonymous),
        ccf::no_auth_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      auto multi_auth = [](auto& ctx) {
        if (
          auto user_cert_ident =
            ctx.template try_get_caller<ccf::UserCertAuthnIdentity>())
        {
          auto response = std::string("User TLS cert");
          response += fmt::format(
            "\nThe caller is a user with ID: {}", user_cert_ident->user_id);
          response += fmt::format(
            "\nThe caller's user data is: {}",
            user_cert_ident->user_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}", user_cert_ident->user_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto member_cert_ident =
            ctx.template try_get_caller<ccf::MemberCertAuthnIdentity>())
        {
          auto response = std::string("Member TLS cert");
          response += fmt::format(
            "\nThe caller is a member with ID: {}",
            member_cert_ident->member_id);
          response += fmt::format(
            "\nThe caller's member data is: {}",
            member_cert_ident->member_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}",
            member_cert_ident->member_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto user_sig_ident =
            ctx.template try_get_caller<ccf::UserSignatureAuthnIdentity>())
        {
          auto response = std::string("User HTTP signature");
          response += fmt::format(
            "\nThe caller is a user with ID: {}", user_sig_ident->user_id);
          response += fmt::format(
            "\nThe caller's user data is: {}",
            user_sig_ident->user_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}", user_sig_ident->user_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto member_sig_ident =
            ctx.template try_get_caller<ccf::MemberSignatureAuthnIdentity>())
        {
          auto response = std::string("Member HTTP signature");
          response += fmt::format(
            "\nThe caller is a member with ID: {}",
            member_sig_ident->member_id);
          response += fmt::format(
            "\nThe caller's member data is: {}",
            member_sig_ident->member_data.dump());
          response += fmt::format(
            "\nThe caller's cert is:\n{}", member_sig_ident->member_cert.str());

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto jwt_ident = ctx.template try_get_caller<ccf::JwtAuthnIdentity>())
        {
          auto response = std::string("JWT");
          response += fmt::format(
            "\nThe caller is identified by a JWT issued by: {}",
            jwt_ident->key_issuer);
          response +=
            fmt::format("\nThe JWT header is:\n{}", jwt_ident->header.dump(2));
          response += fmt::format(
            "\nThe JWT payload is:\n{}", jwt_ident->payload.dump(2));

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        else if (
          auto no_ident =
            ctx.template try_get_caller<ccf::EmptyAuthnIdentity>())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body("Unauthenticated");
          return;
        }
        else
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx.rpc_ctx->set_response_body("Unhandled auth type");
          return;
        }
      };
      make_endpoint(
        "multi_auth",
        HTTP_GET,
        multi_auth,
        {ccf::user_cert_auth_policy,
         ccf::user_signature_auth_policy,
         ccf::member_cert_auth_policy,
         ccf::member_signature_auth_policy,
         ccf::jwt_auth_policy,
         ccf::empty_auth_policy})
        .set_auto_schema<void, std::string>()
        .install();

      // SNIPPET_START: log_record_text
      auto log_record_text = [this](auto& args) {
        const auto expected = http::headervalues::contenttype::TEXT;
        const auto actual =
          args.rpc_ctx->get_request_header(http::headers::CONTENT_TYPE)
            .value_or("");
        if (expected != actual)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(fmt::format(
            "Expected content-type '{}'. Got '{}'.", expected, actual));
          return;
        }

        const auto& path_params = args.rpc_ctx->get_request_path_params();
        const auto id_it = path_params.find("id");
        if (id_it == path_params.end())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            fmt::format("Missing ID component in request path"));
          return;
        }

        const auto id = strtoul(id_it->second.c_str(), nullptr, 10);

        const std::vector<uint8_t>& content = args.rpc_ctx->get_request_body();
        const std::string log_line(content.begin(), content.end());

        auto view = args.tx.get_view(records);
        view->put(id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };
      make_endpoint(
        "log/private/raw_text/{id}",
        HTTP_POST,
        log_record_text,
        user_cert_required)
        .install();
      // SNIPPET_END: log_record_text

      auto get_historical = [this](
                              ccf::EndpointContext& args,
                              ccf::historical::StorePtr historical_store,
                              kv::Consensus::View,
                              kv::Consensus::SeqNo) {
        const auto [pack, params] =
          ccf::jsonhandler::get_json_params(args.rpc_ctx);

        const auto in = params.get<LoggingGetHistorical::In>();

        auto historical_tx = historical_store->create_read_only_tx();
        auto view = historical_tx.get_read_only_view(records);
        const auto v = view->get(in.id);

        if (v.has_value())
        {
          LoggingGetHistorical::Out out;
          out.msg = v.value();
          nlohmann::json j = out;
          ccf::jsonhandler::set_response(std::move(j), args.rpc_ctx, pack);
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        }
      };

      auto is_tx_committed = [this](
                               kv::Consensus::View view,
                               kv::Consensus::SeqNo seqno,
                               std::string& error_reason) {
        if (consensus == nullptr)
        {
          error_reason = "Node is not fully configured";
          return false;
        }

        const auto tx_view = consensus->get_view(seqno);
        const auto committed_seqno = consensus->get_committed_seqno();
        const auto committed_view = consensus->get_view(committed_seqno);

        const auto tx_status = ccf::get_tx_status(
          view, seqno, tx_view, committed_view, committed_seqno);
        if (tx_status != ccf::TxStatus::Committed)
        {
          error_reason = fmt::format(
            "Only committed transactions can be queried. Transaction {}.{} is "
            "{}",
            view,
            seqno,
            ccf::tx_status_to_str(tx_status));
          return false;
        }

        return true;
      };
      make_endpoint(
        "log/private/historical",
        HTTP_GET,
        ccf::historical::adapter(
          get_historical, context.get_historical_state(), is_tx_committed),
        user_cert_required)
        .set_auto_schema<LoggingGetHistorical>()
        .set_forwarding_required(ccf::ForwardingRequired::Never)
        .install();

      auto record_admin_only =
        [this, &nwt](ccf::EndpointContext& ctx, nlohmann::json&& params) {
          {
            const auto& caller_ident =
              ctx.get_caller<ccf::UserCertAuthnIdentity>();

            // SNIPPET_START: user_data_check
            // Check caller's user-data for required permissions
            auto users_view = ctx.tx.get_view(nwt.users);
            const auto user_opt = users_view->get(caller_ident.user_id);
            const nlohmann::json user_data = user_opt.has_value() ?
              user_opt->user_data :
              nlohmann::json(nullptr);
            const auto is_admin_it = user_data.find("isAdmin");

            // Exit if this user has no user data, or the user data is not an
            // object with isAdmin field, or the value of this field is not true
            if (
              !user_data.is_object() || is_admin_it == user_data.end() ||
              !is_admin_it.value().get<bool>())
            {
              return ccf::make_error(
                HTTP_STATUS_FORBIDDEN,
                ccf::errors::AuthorizationFailed,
                "Only admins may access this endpoint.");
            }
            // SNIPPET_END: user_data_check
          }

          const auto in = params.get<LoggingRecord::In>();

          if (in.msg.empty())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "Cannot record an empty log message.");
          }

          auto view = ctx.tx.get_view(records);
          view->put(in.id, in.msg);
          return ccf::make_success(true);
        };
      make_endpoint(
        "log/private/admin_only",
        HTTP_POST,
        ccf::json_adapter(record_admin_only),
        user_cert_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
    }
  };

  class Logger : public ccf::UserRpcFrontend
  {
  private:
    LoggerHandlers logger_handlers;

  public:
    Logger(ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::UserRpcFrontend(*network.tables, logger_handlers),
      logger_handlers(network, context)
    {}

    void open(std::optional<tls::Pem*> identity = std::nullopt) override
    {
      ccf::UserRpcFrontend::open(identity);
      logger_handlers.openapi_info.title = "CCF Sample Logging App";
      logger_handlers.openapi_info.description =
        "This CCF sample app implements a simple logging application, securely "
        "recording messages at client-specified IDs. It demonstrates most of "
        "the features available to CCF apps.";
    }
  };
}

namespace ccfapp
{
  // SNIPPET_START: rpc_handler
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
  {
    return make_shared<loggingapp::Logger>(nwt, context);
  }
  // SNIPPET_END: rpc_handler
}
