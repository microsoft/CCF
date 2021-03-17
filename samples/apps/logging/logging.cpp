// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "formatters.h"
#include "logging_schema.h"
#include "node/historical_queries_adapter.h"
#include "node/quote.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace std;
using namespace nlohmann;

namespace loggingapp
{
  // SNIPPET: table_definition
  using Table = kv::Map<size_t, string>;

  // SNIPPET_START: custom_identity
  struct CustomIdentity : public ccf::AuthnIdentity
  {
    std::string name;
    size_t age;
  };
  // SNIPPET_END: custom_identity

  // SNIPPET_START: custom_auth_policy
  class CustomAuthPolicy : public ccf::AuthnPolicy
  {
  public:
    std::unique_ptr<ccf::AuthnIdentity> authenticate(
      kv::ReadOnlyTx&,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto& headers = ctx->get_request_headers();

      constexpr auto name_header_key = "x-custom-auth-name";
      const auto name_header_it = headers.find(name_header_key);
      if (name_header_it == headers.end())
      {
        error_reason =
          fmt::format("Missing required header {}", name_header_key);
        return nullptr;
      }

      const auto& name = name_header_it->second;
      if (name.empty())
      {
        error_reason = "Name must not be empty";
        return nullptr;
      }

      constexpr auto age_header_key = "x-custom-auth-age";
      const auto age_header_it = headers.find(age_header_key);
      if (name_header_it == headers.end())
      {
        error_reason =
          fmt::format("Missing required header {}", age_header_key);
        return nullptr;
      }

      const auto& age_s = age_header_it->second;
      size_t age;
      const auto [p, ec] =
        std::from_chars(age_s.data(), age_s.data() + age_s.size(), age);
      if (ec != std::errc())
      {
        error_reason =
          fmt::format("Unable to parse age header as a number: {}", age_s);
        return nullptr;
      }

      constexpr auto min_age = 16;
      if (age < min_age)
      {
        error_reason = fmt::format("Caller age must be at least {}", min_age);
        return nullptr;
      }

      auto ident = std::make_unique<CustomIdentity>();
      ident->name = name;
      ident->age = age;
      return ident;
    }

    std::optional<ccf::OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      // There is no OpenAPI-compliant way to describe this auth scheme, so we
      // return nullopt
      return std::nullopt;
    }
  };
  // SNIPPET_END: custom_auth_policy

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

    metrics::Tracker metrics_tracker;

  public:
    // SNIPPET_START: constructor
    LoggerHandlers(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context),
      records("records"),
      public_records("public:records"),
      // SNIPPET_END: constructor
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      const ccf::endpoints::AuthnPolicies auth_policies = {
        ccf::jwt_auth_policy, ccf::user_cert_auth_policy};

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

        auto records_handle = tx.rw(records);
        records_handle->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: install_record
      make_endpoint(
        "log/private", HTTP_POST, ccf::json_adapter(record), auth_policies)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_record

      make_endpoint(
        "log/private",
        ws::Verb::WEBSOCKET,
        ccf::json_adapter(record),
        auth_policies)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get
      auto get = [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          http::parse_query(args.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        auto records_handle = args.tx.ro(records);
        auto record = records_handle->get(id);

        if (record.has_value())
        {
          return ccf::make_success(LoggingGet::Out{record.value()});
        }

        return ccf::make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::ResourceNotFound,
          fmt::format("No such record: {}.", id));
      };
      // SNIPPET_END: get

      // SNIPPET_START: install_get
      make_read_only_endpoint(
        "log/private",
        HTTP_GET,
        ccf::json_read_only_adapter(get),
        auth_policies)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();
      // SNIPPET_END: install_get

      auto remove = [this](ccf::EndpointContext& ctx, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        auto records_handle = ctx.tx.rw(records);
        auto removed = records_handle->remove(id);

        return ccf::make_success(LoggingRemove::Out{removed});
      };
      make_endpoint(
        "log/private", HTTP_DELETE, ccf::json_adapter(remove), auth_policies)
        .set_auto_schema<void, LoggingRemove::Out>()
        .add_query_parameter<size_t>("id")
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

        auto records_handle = tx.rw(public_records);
        records_handle->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record_public
      make_endpoint(
        "log/public",
        HTTP_POST,
        ccf::json_adapter(record_public),
        auth_policies)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get_public
      auto get_public =
        [this](ccf::ReadOnlyEndpointContext& args, nlohmann::json&&) {
          // Parse id from query
          const auto parsed_query =
            http::parse_query(args.rpc_ctx->get_request_query());

          std::string error_reason;
          size_t id;
          if (!http::get_query_value(parsed_query, "id", id, error_reason))
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
          }

          auto public_records_handle = args.tx.ro(public_records);
          auto record = public_records_handle->get(id);

          if (record.has_value())
            return ccf::make_success(LoggingGet::Out{record.value()});

          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ResourceNotFound,
            fmt::format("No such record: {}.", id));
        };
      // SNIPPET_END: get_public
      make_read_only_endpoint(
        "log/public",
        HTTP_GET,
        ccf::json_read_only_adapter(get_public),
        auth_policies)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      auto remove_public = [this](ccf::EndpointContext& ctx, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
        }

        auto records_handle = ctx.tx.rw(public_records);
        auto removed = records_handle->remove(id);

        return ccf::make_success(LoggingRemove::Out{removed});
      };
      make_endpoint(
        "log/public",
        HTTP_DELETE,
        ccf::json_adapter(remove_public),
        auth_policies)
        .set_auto_schema<void, LoggingRemove::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      // SNIPPET_START: log_record_prefix_cert
      auto log_record_prefix_cert = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());

        const auto in = body_j.get<LoggingRecord::In>();
        if (in.msg.empty())
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message");
          return;
        }

        auto cert = mbedtls::make_unique<mbedtls::X509Crt>();

        const auto& cert_data = args.rpc_ctx->session->caller_cert;
        const auto ret = mbedtls_x509_crt_parse(
          cert.get(), cert_data.data(), cert_data.size());
        if (ret != 0)
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Cannot parse x509 caller certificate");
          return;
        }

        const auto log_line = fmt::format("{}: {}", cert->subject, in.msg);
        auto records_handle = args.tx.rw(records);
        records_handle->put(in.id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(true).dump());
      };
      make_endpoint(
        "log/private/prefix_cert",
        HTTP_POST,
        log_record_prefix_cert,
        auth_policies)
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
          auto records_handle = args.tx.rw(records);
          records_handle->put(in.id, log_line);
          return ccf::make_success(true);
        };
      make_endpoint(
        "log/private/anonymous",
        HTTP_POST,
        ccf::json_adapter(log_record_anonymous),
        ccf::no_auth_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      auto multi_auth = [this](auto& ctx) {
        if (
          auto user_cert_ident =
            ctx.template try_get_caller<ccf::UserCertAuthnIdentity>())
        {
          auto response = std::string("User TLS cert");
          response += fmt::format(
            "\nThe caller is a user with ID: {}", user_cert_ident->user_id);
          response += fmt::format(
            "\nThe caller's cert is:\n{}", user_cert_ident->user_cert.str());

          nlohmann::json user_data = nullptr;
          if (
            get_user_data_v1(ctx.tx, user_cert_ident->user_id, user_data) ==
            ccf::ApiResult::OK)
          {
            response +=
              fmt::format("\nThe caller's user data is: {}", user_data.dump());
          }

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
            "\nThe caller's cert is:\n{}",
            member_cert_ident->member_cert.str());

          nlohmann::json member_data = nullptr;
          if (
            get_member_data_v1(
              ctx.tx, member_cert_ident->member_id, member_data) ==
            ccf::ApiResult::OK)
          {
            response += fmt::format(
              "\nThe caller's member data is: {}", member_data.dump());
          }

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
            "\nThe caller's cert is:\n{}", user_sig_ident->user_cert.str());

          nlohmann::json user_data = nullptr;
          if (
            get_user_data_v1(ctx.tx, user_sig_ident->user_id, user_data) ==
            ccf::ApiResult::OK)
          {
            response +=
              fmt::format("\nThe caller's user data is: {}", user_data.dump());
          }

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
            "\nThe caller's cert is:\n{}", member_sig_ident->member_cert.str());

          nlohmann::json member_data = nullptr;
          if (
            get_member_data_v1(
              ctx.tx, member_sig_ident->member_id, member_data) ==
            ccf::ApiResult::OK)
          {
            response += fmt::format(
              "\nThe caller's member data is: {}", member_data.dump());
          }

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
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InvalidInput,
            "Unhandled auth type");
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

      // SNIPPET_START: custom_auth_endpoint
      auto custom_auth = [](auto& ctx) {
        const auto& caller_identity = ctx.template get_caller<CustomIdentity>();
        nlohmann::json response;
        response["name"] = caller_identity.name;
        response["age"] = caller_identity.age;
        response["description"] = fmt::format(
          "Your name is {} and you are {}",
          caller_identity.name,
          caller_identity.age);
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_body(response.dump(2));
      };
      auto custom_policy = std::make_shared<CustomAuthPolicy>();
      make_endpoint("custom_auth", HTTP_GET, custom_auth, {custom_policy})
        .set_auto_schema<void, nlohmann::json>()
        .install();
      // SNIPPET_END: custom_auth_endpoint

      // SNIPPET_START: log_record_text
      auto log_record_text = [this](auto& args) {
        const auto expected = http::headervalues::contenttype::TEXT;
        const auto actual =
          args.rpc_ctx->get_request_header(http::headers::CONTENT_TYPE)
            .value_or("");
        if (expected != actual)
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
            ccf::errors::InvalidHeaderValue,
            fmt::format(
              "Expected content-type '{}'. Got '{}'.", expected, actual));
          return;
        }

        const auto& path_params = args.rpc_ctx->get_request_path_params();
        const auto id_it = path_params.find("id");
        if (id_it == path_params.end())
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Missing ID component in request path");
          return;
        }

        const auto id = strtoul(id_it->second.c_str(), nullptr, 10);

        const std::vector<uint8_t>& content = args.rpc_ctx->get_request_body();
        const std::string log_line(content.begin(), content.end());

        auto records_handle = args.tx.rw(records);
        records_handle->put(id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };
      make_endpoint(
        "log/private/raw_text/{id}", HTTP_POST, log_record_text, auth_policies)
        .install();
      // SNIPPET_END: log_record_text

      // SNIPPET_START: get_historical
      auto get_historical = [this](
                              ccf::EndpointContext& args,
                              ccf::historical::StatePtr historical_state) {
        const auto pack = ccf::jsonhandler::detect_json_pack(args.rpc_ctx);

        // Parse id from query
        const auto parsed_query =
          http::parse_query(args.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id;
        if (!http::get_query_value(parsed_query, "id", id, error_reason))
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
          return;
        }

        auto historical_tx = historical_state->store->create_read_only_tx();
        auto records_handle = historical_tx.ro(records);
        const auto v = records_handle->get(id);

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
        return ccf::historical::is_tx_committed(
          consensus, view, seqno, error_reason);
      };
      make_endpoint(
        "log/private/historical",
        HTTP_GET,
        ccf::historical::adapter(
          get_historical, context.get_historical_state(), is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetHistorical::Out>()
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::ForwardingRequired::Never)
        .install();
      // SNIPPET_END: get_historical

      // SNIPPET_START: get_historical_with_receipt
      auto get_historical_with_receipt =
        [this](
          ccf::EndpointContext& args,
          ccf::historical::StatePtr historical_state) {
          const auto pack = ccf::jsonhandler::detect_json_pack(args.rpc_ctx);

          // Parse id from query
          const auto parsed_query =
            http::parse_query(args.rpc_ctx->get_request_query());

          std::string error_reason;
          size_t id;
          if (!http::get_query_value(parsed_query, "id", id, error_reason))
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }

          auto historical_tx = historical_state->store->create_read_only_tx();
          auto records_handle = historical_tx.ro(records);
          const auto v = records_handle->get(id);

          if (v.has_value())
          {
            LoggingGetReceipt::Out out;
            out.msg = v.value();
            out.receipt.from_receipt(historical_state->receipt);
            ccf::jsonhandler::set_response(std::move(out), args.rpc_ctx, pack);
          }
          else
          {
            args.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
        };
      make_endpoint(
        "log/private/historical_receipt",
        HTTP_GET,
        ccf::historical::adapter(
          get_historical_with_receipt,
          context.get_historical_state(),
          is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetReceipt::Out>()
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::ForwardingRequired::Never)
        .install();
      // SNIPPET_END: get_historical_with_receipt

      static constexpr auto get_historical_range_path =
        "log/private/historical/range";
      auto get_historical_range = [&, this](ccf::EndpointContext& args) {
        // Parse arguments from query
        const auto parsed_query =
          http::parse_query(args.rpc_ctx->get_request_query());

        std::string error_reason;

        size_t from_seqno;
        size_t to_seqno;
        size_t id;
        if (
          !http::get_query_value(
            parsed_query, "from_seqno", from_seqno, error_reason) ||
          !http::get_query_value(
            parsed_query, "to_seqno", to_seqno, error_reason) ||
          !http::get_query_value(parsed_query, "id", id, error_reason))
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
          return;
        }

        // Range must be in order
        if (to_seqno < from_seqno)
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            fmt::format(
              "Invalid range: Starts at {} but ends at {}",
              from_seqno,
              to_seqno));
          return;
        }

        // End of range must be committed
        if (consensus == nullptr)
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Node is not fully operational");
          return;
        }

        const auto view_of_final_seqno = consensus->get_view(to_seqno);
        const auto committed_seqno = consensus->get_committed_seqno();
        const auto committed_view = consensus->get_view(committed_seqno);
        const auto tx_status = ccf::evaluate_tx_status(
          view_of_final_seqno,
          to_seqno,
          view_of_final_seqno,
          committed_view,
          committed_seqno);
        if (tx_status != ccf::TxStatus::Committed)
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            fmt::format(
              "Only committed transactions can be queried. Transaction {}.{} "
              "is "
              "{}",
              view_of_final_seqno,
              to_seqno,
              ccf::tx_status_to_str(tx_status)));
          return;
        }

        // Set a maximum range, paginate larger requests
        static constexpr size_t max_seqno_per_page = 20;
        const auto range_begin = from_seqno;
        const auto range_end =
          std::min(to_seqno, range_begin + max_seqno_per_page);

        // Use hash of request as RequestHandle. WARNING: This means identical
        // requests from different users will collide, and overwrite each
        // other's progress!
        auto make_handle = [](size_t begin, size_t end, size_t id) {
          auto size = sizeof(begin) + sizeof(end) + sizeof(id);
          std::vector<uint8_t> v(size);
          auto data = v.data();
          serialized::write(data, size, begin);
          serialized::write(data, size, end);
          serialized::write(data, size, id);
          return std::hash<decltype(v)>()(v);
        };

        ccf::historical::RequestHandle handle =
          make_handle(range_begin, range_end, id);

        // Fetch the requested range
        auto& historical_cache = context.get_historical_state();

        auto stores =
          historical_cache.get_store_range(handle, range_begin, range_end);
        if (stores.empty())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
          static constexpr size_t retry_after_seconds = 3;
          args.rpc_ctx->set_response_header(
            http::headers::RETRY_AFTER, retry_after_seconds);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(fmt::format(
            "Historical transactions from {} to {} are not yet "
            "available, fetching now",
            range_begin,
            range_end));
          return;
        }

        // Process the fetched Stores
        LoggingGetHistoricalRange::Out response;
        for (size_t i = 0; i < stores.size(); ++i)
        {
          const auto store_seqno = range_begin + i;
          auto& store = stores[i];

          auto historical_tx = store->create_read_only_tx();
          auto records_handle = historical_tx.ro(records);
          const auto v = records_handle->get(id);

          if (v.has_value())
          {
            LoggingGetHistoricalRange::Entry e;
            e.seqno = store_seqno;
            e.id = id;
            e.msg = v.value();
            response.entries.push_back(e);
          }
          // This response do not include any entry when the given key wasn't
          // modified at this seqno. It could instead indicate that the store
          // was checked with an empty tombstone object, but this approach gives
          // smaller responses
        }

        // If this didn't cover the total requested range, begin fetching the
        // next page and tell the caller how to retrieve it
        if (range_end != to_seqno)
        {
          const auto next_page_start = range_end + 1;
          const auto next_page_end =
            std::min(to_seqno, next_page_start + max_seqno_per_page);

          ccf::historical::RequestHandle next_page_handle =
            make_handle(next_page_start, next_page_end, id);
          historical_cache.get_store_range(
            next_page_handle, next_page_start, next_page_end);

          // NB: This path tells the caller to continue to ask until the end of
          // the range, even if the next response is paginated
          response.next_link = fmt::format(
            "/app/{}?from_seqno={}&to_seqno={}&id={}",
            get_historical_range_path,
            next_page_start,
            to_seqno,
            id);
        }

        // Construct the HTTP response
        nlohmann::json j_response = response;
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(j_response.dump());

        // ALSO: Assume this response makes it all the way to the client, and
        // they're finished with it, so we can drop the retrieved state. In a
        // real app this may be driven by a separate client request or an LRU
        historical_cache.drop_request(handle);
      };
      make_endpoint(
        get_historical_range_path,
        HTTP_GET,
        get_historical_range,
        auth_policies)
        .set_auto_schema<void, LoggingGetHistoricalRange::Out>()
        .add_query_parameter<size_t>("from_seqno")
        .add_query_parameter<size_t>("to_seqno")
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::ForwardingRequired::Never)
        .install();

      auto record_admin_only = [this](
                                 ccf::EndpointContext& ctx,
                                 nlohmann::json&& params) {
        const auto& caller_ident = ctx.get_caller<ccf::UserCertAuthnIdentity>();

        // SNIPPET_START: user_data_check
        // Check caller's user-data for required permissions
        nlohmann::json user_data = nullptr;
        auto result = get_user_data_v1(ctx.tx, caller_ident.user_id, user_data);
        if (result == ccf::ApiResult::InternalError)
        {
          return ccf::make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to get user data for user {}: {}",
              caller_ident.user_id,
              ccf::api_result_to_str(result)));
        }
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

        const auto in = params.get<LoggingRecord::In>();

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto view = ctx.tx.rw(records);
        view->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      make_endpoint(
        "log/private/admin_only",
        HTTP_POST,
        ccf::json_adapter(record_admin_only),
        auth_policies)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      metrics_tracker.install_endpoint(*this);
    }

    void tick(
      std::chrono::milliseconds elapsed,
      kv::Consensus::Statistics stats) override
    {
      metrics_tracker.tick(elapsed, stats);

      ccf::UserEndpointRegistry::tick(elapsed, stats);
    }
  };

  class Logger : public ccf::UserRpcFrontend
  {
  private:
    LoggerHandlers logger_handlers;

  public:
    Logger(ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::UserRpcFrontend(*network.tables, logger_handlers),
      logger_handlers(context)
    {}

    void open(std::optional<crypto::Pem*> identity = std::nullopt) override
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
