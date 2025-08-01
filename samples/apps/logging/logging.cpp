// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// This app's includes
#include "logging_schema.h"

// CCF
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/cose_signatures_config_interface.h"
#include "ccf/crypto/cose.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hash.h"
#include "ccf/endpoints/authentication/all_of_auth.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/http_etag.h"
#include "ccf/http_query.h"
#include "ccf/indexing/strategies/seqnos_by_key_bucketed.h"
#include "ccf/indexing/strategy.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace std;
using namespace nlohmann;

namespace loggingapp
{
  // SNIPPET: table_definition
  using RecordsMap = ccf::kv::Map<size_t, string>;
  static constexpr auto PUBLIC_RECORDS = "public:records";
  static constexpr auto PRIVATE_RECORDS = "records";

  // SNIPPET_START: indexing_strategy_definition
  using RecordsIndexingStrategy = ccf::indexing::LazyStrategy<
    ccf::indexing::strategies::SeqnosByKey_Bucketed<RecordsMap>>;
  // SNIPPET_END: indexing_strategy_definition

  // SNIPPET_START: custom_identity
  struct CustomIdentity : public ccf::AuthnIdentity
  {
    std::string name;
    size_t age = 0;
  };
  // SNIPPET_END: custom_identity

  struct MatchHeaders
  {
    std::optional<std::string> if_match;
    std::optional<std::string> if_none_match;

    MatchHeaders(const std::shared_ptr<ccf::RpcContext>& rpc_ctx) :
      if_match(rpc_ctx->get_request_header("if-match")),
      if_none_match(rpc_ctx->get_request_header("if-none-match"))
    {}

    [[nodiscard]] bool conflict() const
    {
      return if_match.has_value() && if_none_match.has_value();
    }

    [[nodiscard]] bool empty() const
    {
      return !if_match.has_value() && !if_none_match.has_value();
    }
  };

  // SNIPPET_START: custom_auth_policy
  class CustomAuthPolicy : public ccf::AuthnPolicy
  {
  public:
    std::unique_ptr<ccf::AuthnIdentity> authenticate(
      [[maybe_unused]] ccf::kv::ReadOnlyTx& ro_tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto& headers = ctx->get_request_headers();

      {
        // If a specific header is present, throw an exception to simulate a
        // dangerously implemented auth policy
        constexpr auto explode_header_key = "x-custom-auth-explode";
        const auto explode_header_it = headers.find(explode_header_key);
        if (explode_header_it != headers.end())
        {
          throw std::logic_error(explode_header_it->second);
        }
      }

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
      if (age_header_it == headers.end())
      {
        error_reason =
          fmt::format("Missing required header {}", age_header_key);
        return nullptr;
      }

      const auto& age_s = age_header_it->second;
      size_t age = 0;
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

    [[nodiscard]] std::optional<ccf::OpenAPISecuritySchema>
    get_openapi_security_schema() const override
    {
      // There is no OpenAPI-compliant way to describe this auth scheme, so we
      // return nullopt
      return std::nullopt;
    }

    std::string get_security_scheme_name() override
    {
      return "CustomAuthPolicy";
    }
  };
  // SNIPPET_END: custom_auth_policy

  class CommittedRecords : public ccf::indexing::Strategy
  {
  private:
    std::string map_name;
    std::map<size_t, std::string> records;
    std::mutex txid_lock;
    ccf::TxID current_txid = {};

  public:
    CommittedRecords(
      const std::string& map_name_, const ccf::TxID& initial_txid = {}) :
      ccf::indexing::Strategy(fmt::format("CommittedRecords {}", map_name_)),
      map_name(map_name_),
      current_txid(initial_txid)
    {}

    void handle_committed_transaction(
      const ccf::TxID& tx_id, const ccf::kv::ReadOnlyStorePtr& store) override
    {
      std::lock_guard<std::mutex> lock(txid_lock);
      auto tx_diff = store->create_tx_diff();
      auto* m = tx_diff.template diff<RecordsMap>(map_name);
      m->foreach([this](const size_t& k, std::optional<std::string> v) -> bool {
        if (v.has_value())
        {
          std::string val = v.value();
          records[k] = val;
        }
        else
        {
          records.erase(k);
        }

        return true;
      });
      current_txid = tx_id;
    }

    std::optional<ccf::SeqNo> next_requested() override
    {
      std::lock_guard<std::mutex> lock(txid_lock);
      return current_txid.seqno + 1;
    }

    std::optional<std::string> get(size_t id)
    {
      auto search = records.find(id);
      if (search == records.end())
      {
        return std::nullopt;
      }
      return search->second;
    }

    ccf::TxID get_current_txid()
    {
      std::lock_guard<std::mutex> lock(txid_lock);
      return current_txid;
    }
  };

  // SNIPPET: inherit_frontend
  class LoggerHandlers : public ccf::UserEndpointRegistry
  {
  private:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    ccf::AbstractNodeContext& _context;
    nlohmann::json record_public_params_schema;
    nlohmann::json record_public_result_schema;

    nlohmann::json get_public_params_schema;
    nlohmann::json get_public_result_schema;

    std::shared_ptr<RecordsIndexingStrategy> index_per_public_key = nullptr;
    std::shared_ptr<CommittedRecords> committed_records = nullptr;

    std::string describe_identity(
      ccf::endpoints::EndpointContext& ctx,
      const std::unique_ptr<ccf::AuthnIdentity>& caller)
    {
      if (
        const auto* user_cert_ident =
          dynamic_cast<const ccf::UserCertAuthnIdentity*>(caller.get()))
      {
        auto response = std::string("User TLS cert");
        response += fmt::format(
          "\nThe caller is a user with ID: {}", user_cert_ident->user_id);

        ccf::crypto::Pem user_cert;
        if (
          get_user_cert_v1(ctx.tx, user_cert_ident->user_id, user_cert) ==
          ccf::ApiResult::OK)
        {
          response +=
            fmt::format("\nThe caller's cert is:\n{}", user_cert.str());
        }

        nlohmann::json user_data = nullptr;
        if (
          get_user_data_v1(ctx.tx, user_cert_ident->user_id, user_data) ==
          ccf::ApiResult::OK)
        {
          response +=
            fmt::format("\nThe caller's user data is: {}", user_data.dump());
        }

        return response;
      }

      if (
        const auto* member_cert_ident =
          dynamic_cast<const ccf::MemberCertAuthnIdentity*>(caller.get()))
      {
        auto response = std::string("Member TLS cert");
        response += fmt::format(
          "\nThe caller is a member with ID: {}", member_cert_ident->member_id);

        ccf::crypto::Pem member_cert;
        if (
          get_member_cert_v1(
            ctx.tx, member_cert_ident->member_id, member_cert) ==
          ccf::ApiResult::OK)
        {
          response +=
            fmt::format("\nThe caller's cert is:\n{}", member_cert.str());
        }

        nlohmann::json member_data = nullptr;
        if (
          get_member_data_v1(
            ctx.tx, member_cert_ident->member_id, member_data) ==
          ccf::ApiResult::OK)
        {
          response += fmt::format(
            "\nThe caller's member data is: {}", member_data.dump());
        }

        return response;
      }

      if (
        const auto* any_cert_ident =
          dynamic_cast<const ccf::AnyCertAuthnIdentity*>(caller.get()))
      {
        auto response = std::string("Any TLS cert");
        auto caller_cert = ccf::crypto::cert_der_to_pem(any_cert_ident->cert);

        response +=
          fmt::format("\nThe caller's cert is:\n{}", caller_cert.str());
        return response;
      }

      if (
        const auto* jwt_ident =
          dynamic_cast<const ccf::JwtAuthnIdentity*>(caller.get()))
      {
        auto response = std::string("JWT");
        response += fmt::format(
          "\nThe caller is identified by a JWT issued by: {}",
          jwt_ident->key_issuer);
        response +=
          fmt::format("\nThe JWT header is:\n{}", jwt_ident->header.dump(2));
        response +=
          fmt::format("\nThe JWT payload is:\n{}", jwt_ident->payload.dump(2));

        return response;
      }

      if (
        const auto* cose_ident =
          dynamic_cast<const ccf::UserCOSESign1AuthnIdentity*>(caller.get()))
      {
        auto response = std::string("User COSE Sign1");
        response += fmt::format(
          "\nThe caller is identified by a COSE Sign1 signed by kid: {}",
          cose_ident->user_id);
        response += fmt::format(
          "\nThe caller is identified by a COSE Sign1 with content of size: "
          "{}",
          cose_ident->content.size());

        return response;
      }

      if (
        const auto* no_ident =
          dynamic_cast<const ccf::EmptyAuthnIdentity*>(caller.get()))
      {
        return "Unauthenticated";
      }

      if (
        const auto* all_of_ident =
          dynamic_cast<const ccf::AllOfAuthnIdentity*>(caller.get()))
      {
        auto response = fmt::format(
          "Conjoined auth policy: {}", all_of_ident->get_conjoined_name());

        for (const auto& [name, sub_ident] : all_of_ident->identities)
        {
          response += fmt::format("\n\n{}:\n", name);
          response += describe_identity(ctx, sub_ident);
        }

        return response;
      }

      return "";
    }

    std::optional<ccf::TxStatus> get_tx_status(ccf::SeqNo seqno)
    {
      ccf::ApiResult result = ccf::ApiResult::OK;

      ccf::View view_of_seqno = 0;
      result = get_view_for_seqno_v1(seqno, view_of_seqno);
      if (result == ccf::ApiResult::OK)
      {
        ccf::TxStatus status = {};
        result = get_status_for_txid_v1(view_of_seqno, seqno, status);
        if (result == ccf::ApiResult::OK)
        {
          return status;
        }
      }
      else if (result == ccf::ApiResult::NotFound)
      {
        return ccf::TxStatus::Unknown;
      }

      return std::nullopt;
    }

    static std::optional<std::string> get_scope(auto& ctx)
    {
      const auto parsed_query =
        ccf::http::parse_query(ctx.rpc_ctx->get_request_query());
      std::string error_string;
      return ccf::http::get_query_value_opt<std::string>(
        parsed_query, "scope", error_string);
    }

    static std::string private_records(auto& ctx)
    {
      return private_records(get_scope(ctx));
    }

    static std::string public_records(auto& ctx)
    {
      return public_records(get_scope(ctx));
    }

    static std::string private_records(const std::optional<std::string>& scope)
    {
      return scope.has_value() ? fmt::format("{}-{}", PRIVATE_RECORDS, *scope) :
                                 PRIVATE_RECORDS;
    }

    static std::string public_records(const std::optional<std::string>& scope)
    {
      return scope.has_value() ? fmt::format("{}-{}", PUBLIC_RECORDS, *scope) :
                                 PUBLIC_RECORDS;
    }

    // Wrap all endpoints with trace logging of their invocation
    ccf::endpoints::Endpoint make_endpoint(
      const std::string& method,
      ccf::RESTVerb verb,
      const ccf::endpoints::EndpointFunction& f,
      const ccf::AuthnPolicies& ap) override
    {
      return ccf::UserEndpointRegistry::make_endpoint(
        method,
        verb,
        [method, verb, f](ccf::endpoints::EndpointContext& args) {
          CCF_APP_TRACE("BEGIN {} {}", verb.c_str(), method);
          f(args);
          CCF_APP_TRACE("END   {} {}", verb.c_str(), method);
        },
        ap);
    }

    // Wrap all endpoints with trace logging of their invocation
    ccf::endpoints::Endpoint make_endpoint_with_local_commit_handler(
      const std::string& method,
      ccf::RESTVerb verb,
      const ccf::endpoints::EndpointFunction& f,
      const ccf::endpoints::LocallyCommittedEndpointFunction& lcf,
      const ccf::AuthnPolicies& ap) override
    {
      return ccf::UserEndpointRegistry::make_endpoint_with_local_commit_handler(
        method,
        verb,
        [method, verb, f](ccf::endpoints::EndpointContext& args) {
          CCF_APP_TRACE("BEGIN {} {}", verb.c_str(), method);
          f(args);
          CCF_APP_TRACE("END   {} {}", verb.c_str(), method);
        },
        [method, verb, lcf](
          ccf::endpoints::CommandEndpointContext& args, const ccf::TxID& txid) {
          CCF_APP_TRACE(
            "BEGIN LOCAL COMMIT HANDLER {} {}", verb.c_str(), method);
          lcf(args, txid);
          CCF_APP_TRACE(
            "END LOCAL COMMIT HANDLER   {} {}", verb.c_str(), method);
        },
        ap);
    }

  public:
    LoggerHandlers(ccf::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context),
      _context(context),
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      openapi_info.title = "CCF Sample Logging App";
      openapi_info.description =
        "This CCF sample app implements a simple logging application, securely "
        "recording messages at client-specified IDs. It demonstrates most of "
        "the features available to CCF apps.";

      openapi_info.document_version = "2.8.0";
    };

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      constexpr size_t seqnos_per_bucket = 10000;
      constexpr size_t buckets_per_key = 20;

      index_per_public_key = std::make_shared<RecordsIndexingStrategy>(
        PUBLIC_RECORDS, context, seqnos_per_bucket, buckets_per_key);
      context.get_indexing_strategies().install_strategy(index_per_public_key);

      const ccf::AuthnPolicies auth_policies = {
        ccf::jwt_auth_policy,
        ccf::user_cert_auth_policy,
        ccf::user_cose_sign1_auth_policy};

      // SNIPPET_START: record
      auto record = [this](auto& ctx, nlohmann::json&& params) {
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

        // SNIPPET: private_table_access
        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        // SNIPPET_END: private_table_access
        records_handle->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: install_record
      make_endpoint(
        "/log/private", HTTP_POST, ccf::json_adapter(record), auth_policies)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: install_record

      auto add_txid_in_body_put = [](auto& ctx, const auto& tx_id) {
        static constexpr auto CCF_TX_ID = "x-ms-ccf-transaction-id";
        ctx.rpc_ctx->set_response_header(CCF_TX_ID, tx_id.to_str());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);

        auto* out = static_cast<LoggingPut::Out*>(ctx.rpc_ctx->get_user_data());

        if (out == nullptr)
        {
          throw std::runtime_error("didn't set user_data!");
        }

        out->tx_id = tx_id.to_str();

        ctx.rpc_ctx->set_response_body(nlohmann::json(*out).dump());
      };

      auto record_v2 = [this](auto& ctx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        records_handle->put(in.id, in.msg);

        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        std::string fail;
        ccf::http::get_query_value(parsed_query, "fail", fail, error_reason);

        auto out = std::make_shared<LoggingPut::Out>();
        out->success = true;

        if (fail != "true")
        {
          ctx.rpc_ctx->set_user_data(out);
        }

        // return a default value as we'll set the response in the post-commit
        // handler
        return ccf::make_success(nullptr);
      };

      make_endpoint_with_local_commit_handler(
        "/log/private/anonymous/v2",
        HTTP_POST,
        ccf::json_adapter(record_v2),
        add_txid_in_body_put,
        ccf::no_auth_required)
        .set_auto_schema<LoggingRecord::In, LoggingPut::Out>()
        .install();

      // SNIPPET_START: get
      auto get = [this](auto& ctx, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            error_reason);
        }

        auto records_handle =
          ctx.tx.template ro<RecordsMap>(private_records(ctx));
        auto record = records_handle->get(id);

        if (record.has_value())
        {
          return ccf::make_success(LoggingGet::Out{record.value()});
        }

        return ccf::make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          fmt::format("No such record: {}.", id));
      };
      // SNIPPET_END: get

      // SNIPPET_START: install_get
      make_read_only_endpoint(
        "/log/private",
        HTTP_GET,
        ccf::json_read_only_adapter(get),
        auth_policies)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();
      // SNIPPET_END: install_get

      make_read_only_endpoint(
        "/log/private/backup",
        HTTP_GET,
        ccf::json_read_only_adapter(get),
        auth_policies)
        .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::ToBackup)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      // install the committed index and tell the historical fetcher to keep
      // track of deleted keys too, so that the index can observe the deleted
      // keys.
      auto install_committed_index = [this](auto& ctx) {
        if (committed_records != nullptr)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_PRECONDITION_FAILED);
          ctx.rpc_ctx->set_response_body("Already installed");
          return;
        }

        ccf::View view = 0;
        ccf::SeqNo seqno = 0;
        auto result = get_last_committed_txid_v1(view, seqno);
        if (result != ccf::ApiResult::OK)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          ctx.rpc_ctx->set_response_body(fmt::format(
            "Failed to retrieve current committed TxID: {}", result));
          return;
        }

        // tracking committed records also wants to track deletes so enable that
        // in the historical queries too
        _context.get_historical_state().track_deletes_on_missing_keys(true);

        // Indexing from the start of time may be expensive. Since this is a
        // locally-targetted sample, we only index from the _currently_
        // committed TxID
        committed_records = std::make_shared<CommittedRecords>(
          PRIVATE_RECORDS, ccf::TxID{view, seqno});

        _context.get_indexing_strategies().install_strategy(committed_records);
      };

      make_command_endpoint(
        "/log/private/install_committed_index",
        HTTP_POST,
        install_committed_index,
        ccf::no_auth_required)
        .set_auto_schema<void, void>()
        .install();

      auto uninstall_committed_index = [this](auto& ctx) {
        if (committed_records == nullptr)
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_PRECONDITION_FAILED);
          ctx.rpc_ctx->set_response_body("Not currently installed");
          return;
        }

        _context.get_indexing_strategies().uninstall_strategy(
          committed_records);
        committed_records = nullptr;
      };

      make_command_endpoint(
        "/log/private/uninstall_committed_index",
        HTTP_POST,
        uninstall_committed_index,
        ccf::no_auth_required)
        .set_auto_schema<void, void>()
        .install();

      auto get_committed = [this](auto& ctx) {
        // Parse id from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          auto response = nlohmann::json{{
            "error",
            {
              {"code", ccf::errors::InvalidQueryParameterValue},
              {"message", std::move(error_reason)},
            },
          }};

          ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_BAD_REQUEST);
          return;
        }

        auto record = committed_records->get(id);

        if (record.has_value())
        {
          nlohmann::json response = LoggingGet::Out{record.value()};
          ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_OK);
          return;
        }

        auto response = nlohmann::json{{
          "error",
          {
            {"code", ccf::errors::ResourceNotFound},
            {"message", fmt::format("No such record: {}.", id)},
            {"current_txid", committed_records->get_current_txid().to_str()},
          },
        }};

        ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_BAD_REQUEST);
      };

      make_read_only_endpoint(
        "/log/private/committed",
        HTTP_GET,
        get_committed,
        ccf::no_auth_required)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      auto remove = [this](auto& ctx, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            error_reason);
        }

        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        auto had = records_handle->has(id);
        records_handle->remove(id);

        return ccf::make_success(LoggingRemove::Out{had});
      };
      make_endpoint(
        "/log/private", HTTP_DELETE, ccf::json_adapter(remove), auth_policies)
        .set_auto_schema<void, LoggingRemove::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      auto clear = [this](auto& ctx, nlohmann::json&&) {
        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        records_handle->clear();
        return ccf::make_success(true);
      };
      make_endpoint(
        "/log/private/all",
        HTTP_DELETE,
        ccf::json_adapter(clear),
        auth_policies)
        .set_auto_schema<void, bool>()
        .install();

      auto count = [this](auto& ctx, nlohmann::json&&) {
        auto records_handle =
          ctx.tx.template ro<RecordsMap>(private_records(ctx));
        return ccf::make_success(records_handle->size());
      };
      make_endpoint(
        "/log/private/count", HTTP_GET, ccf::json_adapter(count), auth_policies)
        .set_auto_schema<void, size_t>()
        .install();

      // SNIPPET_START: record_public
      auto record_public = [this](auto& ctx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        // SNIPPET: public_table_access
        auto records_handle =
          ctx.tx.template rw<RecordsMap>(public_records(ctx));
        // SNIPPET_END: public_table_access
        const auto id = params["id"].get<size_t>();

        // SNIPPET_START: public_table_post_match
        MatchHeaders match_headers(ctx.rpc_ctx);
        if (match_headers.conflict())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidHeaderValue,
            "Cannot have both If-Match and If-None-Match headers.");
        }

        // The presence of a Match header requires a read dependency
        // to check the value matches the constraint
        if (!match_headers.empty())
        {
          auto current_value = records_handle->get(id);
          if (current_value.has_value())
          {
            ccf::crypto::Sha256Hash value_digest(current_value.value());
            auto etag = value_digest.hex_str();

            // On a POST operation, If-Match failing or If-None-Match passing
            // both return a 412 Precondition Failed to be returned, and no
            // side-effect.
            if (match_headers.if_match.has_value())
            {
              ccf::http::Matcher matcher(match_headers.if_match.value());
              if (!matcher.matches(etag))
              {
                return ccf::make_error(
                  HTTP_STATUS_PRECONDITION_FAILED,
                  ccf::errors::PreconditionFailed,
                  "Resource has changed.");
              }
            }

            if (match_headers.if_none_match.has_value())
            {
              ccf::http::Matcher matcher(match_headers.if_none_match.value());
              if (matcher.matches(etag))
              {
                return ccf::make_error(
                  HTTP_STATUS_PRECONDITION_FAILED,
                  ccf::errors::PreconditionFailed,
                  "Resource has changed.");
              }
            }
          }
        }
        // SNIPPET_END: public_table_post_match

        records_handle->put(id, in.msg);
        // SNIPPET_START: set_claims_digest
        if (in.record_claim)
        {
          ctx.rpc_ctx->set_claims_digest(ccf::ClaimsDigest::Digest(in.msg));
        }
        // SNIPPET_END: set_claims_digest
        CCF_APP_INFO("Storing {} = {}", id, in.msg);

        // SNIPPET_START: public_table_post_etag
        ccf::crypto::Sha256Hash value_digest(in.msg);
        // Succesful calls set an ETag
        ctx.rpc_ctx->set_response_header("ETag", value_digest.hex_str());
        // SNIPPET_END: public_table_post_etag

        return ccf::make_success(true);
      };
      // SNIPPET_END: record_public
      make_endpoint(
        "/log/public",
        HTTP_POST,
        ccf::json_adapter(record_public),
        auth_policies)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      // SNIPPET_START: get_public
      auto get_public = [this](auto& ctx, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            error_reason);
        }

        auto public_records_handle =
          ctx.tx.template ro<RecordsMap>(public_records(ctx));
        auto record = public_records_handle->get(id);

        // SNIPPET_START: public_table_get_match
        // If there is not value, the response is always Not Found
        // regardless of Match headers
        if (record.has_value())
        {
          MatchHeaders match_headers(ctx.rpc_ctx);
          if (match_headers.conflict())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidHeaderValue,
              "Cannot have both If-Match and If-None-Match headers.");
          }

          // If a record is present, compute an Entity Tag, and apply
          // If-Match and If-None-Match.
          ccf::crypto::Sha256Hash value_digest(record.value());
          const auto etag = value_digest.hex_str();

          if (match_headers.if_match.has_value())
          {
            ccf::http::Matcher matcher(match_headers.if_match.value());
            if (!matcher.matches(etag))
            {
              return ccf::make_error(
                HTTP_STATUS_PRECONDITION_FAILED,
                ccf::errors::PreconditionFailed,
                "Resource has changed.");
            }
          }

          // On a GET, If-None-Match passing returns 304 Not Modified
          if (match_headers.if_none_match.has_value())
          {
            ccf::http::Matcher matcher(match_headers.if_none_match.value());
            if (matcher.matches(etag))
            {
              return ccf::make_redirect(HTTP_STATUS_NOT_MODIFIED);
            }
          }

          // Succesful calls set an ETag
          ctx.rpc_ctx->set_response_header("ETag", etag);
          CCF_APP_INFO("Fetching {} = {}", id, record.value());
          return ccf::make_success(LoggingGet::Out{record.value()});
        }
        // SNIPPET_END: public_table_get_match

        CCF_APP_INFO("Fetching - no entry for {}", id);
        return ccf::make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          fmt::format("No such record: {}.", id));
      };
      // SNIPPET_END: get_public
      make_read_only_endpoint(
        "/log/public",
        HTTP_GET,
        ccf::json_read_only_adapter(get_public),
        auth_policies)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      make_read_only_endpoint(
        "/log/public/backup",
        HTTP_GET,
        ccf::json_read_only_adapter(get_public),
        auth_policies)
        .set_redirection_strategy(ccf::endpoints::RedirectionStrategy::ToBackup)
        .set_auto_schema<void, LoggingGet::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      auto remove_public = [this](auto& ctx, nlohmann::json&&) {
        // Parse id from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            error_reason);
        }

        auto records_handle =
          ctx.tx.template rw<RecordsMap>(public_records(ctx));
        auto current_value = records_handle->get(id);

        // SNIPPET_START: public_table_delete_match
        // If there is no value, we don't need to look at the Match
        // headers to report that the value is deleted (200 OK)
        if (current_value.has_value())
        {
          MatchHeaders match_headers(ctx.rpc_ctx);
          if (match_headers.conflict())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidHeaderValue,
              "Cannot have both If-Match and If-None-Match headers.");
          }

          if (!match_headers.empty())
          {
            // If a Match header is present, we need to compute the ETag
            // to resolve the constraints
            ccf::crypto::Sha256Hash value_digest(current_value.value());
            const auto etag = value_digest.hex_str();

            if (match_headers.if_match.has_value())
            {
              ccf::http::Matcher matcher(match_headers.if_match.value());
              if (!matcher.matches(etag))
              {
                return ccf::make_error(
                  HTTP_STATUS_PRECONDITION_FAILED,
                  ccf::errors::PreconditionFailed,
                  "Resource has changed.");
              }
            }

            if (match_headers.if_none_match.has_value())
            {
              ccf::http::Matcher matcher(match_headers.if_none_match.value());
              if (matcher.matches(etag))
              {
                return ccf::make_redirect(HTTP_STATUS_NOT_MODIFIED);
              }
            }
          }
        }
        // SNIPPET_END: public_table_delete_match

        // Succesful calls remove the value, and therefore do not set an ETag
        records_handle->remove(id);
        return ccf::make_success(LoggingRemove::Out{current_value.has_value()});
      };
      make_endpoint(
        "/log/public",
        HTTP_DELETE,
        ccf::json_adapter(remove_public),
        auth_policies)
        .set_auto_schema<void, LoggingRemove::Out>()
        .add_query_parameter<size_t>("id")
        .install();

      auto clear_public = [this](auto& ctx, nlohmann::json&&) {
        auto public_records_handle =
          ctx.tx.template rw<RecordsMap>(public_records(ctx));
        public_records_handle->clear();
        return ccf::make_success(true);
      };
      make_endpoint(
        "/log/public/all",
        HTTP_DELETE,
        ccf::json_adapter(clear_public),
        auth_policies)
        .set_auto_schema<void, bool>()
        .install();

      auto count_public = [this](auto& ctx, nlohmann::json&&) {
        auto public_records_handle =
          ctx.tx.template ro<RecordsMap>(public_records(ctx));
        return ccf::make_success(public_records_handle->size());
      };
      make_endpoint(
        "/log/public/count",
        HTTP_GET,
        ccf::json_adapter(count_public),
        auth_policies)
        .set_auto_schema<void, size_t>()
        .install();

      // SNIPPET_START: log_record_prefix_cert
      auto log_record_prefix_cert = [this](auto& ctx) {
        const auto& caller_ident =
          ctx.template get_caller<ccf::UserCertAuthnIdentity>();

        const nlohmann::json body_j =
          nlohmann::json::parse(ctx.rpc_ctx->get_request_body());

        const auto in = body_j.get<LoggingRecord::In>();
        if (in.msg.empty())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message");
          return;
        }

        const auto log_line =
          fmt::format("{}: {}", caller_ident.user_id.value(), in.msg);
        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        records_handle->put(in.id, log_line);

        ctx.rpc_ctx->set_response_json(true, HTTP_STATUS_OK);
      };
      make_endpoint(
        "/log/private/prefix_cert",
        HTTP_POST,
        log_record_prefix_cert,
        {ccf::user_cert_auth_policy})
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_END: log_record_prefix_cert

      auto log_record_anonymous = [this](auto& ctx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();
        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Cannot record an empty log message.");
        }

        const auto log_line = fmt::format("Anonymous: {}", in.msg);
        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        records_handle->put(in.id, log_line);
        return ccf::make_success(true);
      };
      make_endpoint(
        "/log/private/anonymous",
        HTTP_POST,
        ccf::json_adapter(log_record_anonymous),
        ccf::no_auth_required)
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      auto user_cert_jwt_and_sig_auth_policy =
        std::make_shared<ccf::AllOfAuthnPolicy>(
          std::vector<std::shared_ptr<ccf::AuthnPolicy>>{
            ccf::user_cert_auth_policy,
            ccf::jwt_auth_policy,
            ccf::user_cose_sign1_auth_policy});

      auto multi_auth = [this, user_cert_jwt_and_sig_auth_policy](auto& ctx) {
        auto response = describe_identity(ctx, ctx.caller);
        if (!response.empty())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(response));
          return;
        }
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InvalidInput,
          "Unhandled auth type");
        return;
      };
      make_endpoint(
        "/multi_auth",
        HTTP_POST,
        multi_auth,
        {// Needs to come first, otherwise a less-restrictive policy will be
         // accepted first
         user_cert_jwt_and_sig_auth_policy,
         ccf::user_cert_auth_policy,
         ccf::member_cert_auth_policy,
         ccf::any_cert_auth_policy,
         ccf::jwt_auth_policy,
         ccf::user_cose_sign1_auth_policy,
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
      make_endpoint("/custom_auth", HTTP_GET, custom_auth, {custom_policy})
        .set_auto_schema<void, nlohmann::json>()
        // To test that custom auth works on both the receiving node and a
        // forwardee, we always forward it
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Always)
        .install();
      // SNIPPET_END: custom_auth_endpoint

      // SNIPPET_START: log_record_text
      auto log_record_text = [this](auto& ctx) {
        const auto* const expected = ccf::http::headervalues::contenttype::TEXT;
        const auto actual =
          ctx.rpc_ctx->get_request_header(ccf::http::headers::CONTENT_TYPE)
            .value_or("");
        if (expected != actual)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE,
            ccf::errors::InvalidHeaderValue,
            fmt::format(
              "Expected content-type '{}'. Got '{}'.", expected, actual));
          return;
        }

        const auto& path_params = ctx.rpc_ctx->get_request_path_params();
        const auto id_it = path_params.find("id");
        if (id_it == path_params.end())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            "Missing ID component in request path");
          return;
        }

        const auto id = strtoul(id_it->second.c_str(), nullptr, 10);

        const std::vector<uint8_t>& content = ctx.rpc_ctx->get_request_body();
        const std::string log_line(content.begin(), content.end());

        auto records_handle =
          ctx.tx.template rw<RecordsMap>(private_records(ctx));
        records_handle->put(id, log_line);

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };
      make_endpoint(
        "/log/private/raw_text/{id}", HTTP_POST, log_record_text, auth_policies)
        .install();
      // SNIPPET_END: log_record_text

      // SNIPPET_START: get_historical
      auto get_historical = [this](
                              ccf::endpoints::ReadOnlyEndpointContext& ctx,
                              ccf::historical::StatePtr historical_state) {
        // Parse id from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;
        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
          return;
        }

        auto historical_tx = historical_state->store->create_read_only_tx();
        auto* records_handle =
          historical_tx.template ro<RecordsMap>(private_records(ctx));
        const auto v = records_handle->get(id);

        if (v.has_value())
        {
          LoggingGetHistorical::Out out;
          out.msg = v.value();
          nlohmann::json j = out;
          ccf::jsonhandler::set_response(std::move(j), ctx.rpc_ctx);
        }
        else
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        }
      };

      auto is_tx_committed =
        [this](ccf::View view, ccf::SeqNo seqno, std::string& error_reason) {
          return ccf::historical::is_tx_committed_v2(
            consensus, view, seqno, error_reason);
        };
      make_read_only_endpoint(
        "/log/private/historical",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_historical, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetHistorical::Out>()
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
      // SNIPPET_END: get_historical

      // SNIPPET_START: get_historical_with_receipt
      auto get_historical_with_receipt =
        [this](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr historical_state) {
          // Parse id from query
          const auto parsed_query =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

          std::string error_reason;
          size_t id = 0;
          if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }

          auto historical_tx = historical_state->store->create_read_only_tx();
          auto* records_handle =
            historical_tx.template ro<RecordsMap>(private_records(ctx));
          const auto v = records_handle->get(id);

          if (v.has_value())
          {
            LoggingGetReceipt::Out out;
            out.msg = v.value();
            assert(historical_state->receipt);
            out.receipt = ccf::describe_receipt_v1(*historical_state->receipt);
            ccf::jsonhandler::set_response(std::move(out), ctx.rpc_ctx);
          }
          else
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
        };
      make_read_only_endpoint(
        "/log/private/historical_receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_historical_with_receipt, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetReceipt::Out>()
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
      // SNIPPET_END: get_historical_with_receipt

      auto get_historical_with_receipt_and_claims =
        [this](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr historical_state) {
          // Parse id from query
          const auto parsed_query =
            ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

          std::string error_reason;
          size_t id = 0;
          if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }

          auto historical_tx = historical_state->store->create_read_only_tx();
          auto* records_handle =
            historical_tx.template ro<RecordsMap>(public_records(ctx));
          const auto v = records_handle->get(id);

          if (v.has_value())
          {
            LoggingGetReceipt::Out out;
            out.msg = v.value();
            assert(historical_state->receipt);
            // SNIPPET_START: claims_digest_in_receipt
            // Claims are expanded as out.msg, so the claims digest is removed
            // from the receipt to force verification to re-compute it.
            auto full_receipt =
              ccf::describe_receipt_v1(*historical_state->receipt);
            out.receipt = full_receipt;
            out.receipt["leaf_components"].erase("claims_digest");
            // SNIPPET_END: claims_digest_in_receipt
            ccf::jsonhandler::set_response(std::move(out), ctx.rpc_ctx);
          }
          else
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
        };
      make_read_only_endpoint(
        "/log/public/historical_receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_historical_with_receipt_and_claims, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetReceipt::Out>()
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
      // SNIPPET_END: get_historical_with_receipt

      static constexpr auto get_historical_range_path =
        "/log/public/historical/range";
      auto get_historical_range = [&,
                                   this](ccf::endpoints::EndpointContext& ctx) {
        // Parse arguments from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;

        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
          return;
        }

        size_t from_seqno = 0;
        if (!ccf::http::get_query_value(
              parsed_query, "from_seqno", from_seqno, error_reason))
        {
          // If no from_seqno is specified, defaults to very first transaction
          // in ledger
          from_seqno = 1;
        }

        size_t to_seqno = 0;
        if (!ccf::http::get_query_value(
              parsed_query, "to_seqno", to_seqno, error_reason))
        {
          // If no end point is specified, use the last time this ID was
          // written to
          auto* records = ctx.tx.ro<RecordsMap>(public_records(ctx));
          const auto last_written_version =
            records->get_version_of_previous_write(id);
          if (last_written_version.has_value())
          {
            to_seqno = last_written_version.value();
          }
          else
          {
            // If there's no last written version, it may have never been
            // written but may simply be currently deleted. Use current commit
            // index as end point to ensure we include any deleted entries.
            ccf::View view = 0;
            ccf::SeqNo seqno = 0;
            const auto result = get_last_committed_txid_v1(view, seqno);
            if (result != ccf::ApiResult::OK)
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format(
                  "Failed to get committed transaction: {}",
                  ccf::api_result_to_str(result)));
            }
            to_seqno = seqno;
          }
        }

        // Range must be in order
        if (to_seqno < from_seqno)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            fmt::format(
              "Invalid range: Starts at {} but ends at {}",
              from_seqno,
              to_seqno));
          return;
        }

        // End of range must be committed
        const auto tx_status = get_tx_status(to_seqno);
        if (
          !tx_status.has_value() ||
          tx_status.value() != ccf::TxStatus::Committed)
        {
          const auto* const tx_status_msg = tx_status.has_value() ?
            tx_status_to_str(tx_status.value()) :
            "not found";
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            fmt::format(
              "Only committed transactions can be queried. Transaction at "
              "seqno {} is {}",
              to_seqno,
              tx_status_msg));
          return;
        }

        const auto indexed_txid = index_per_public_key->get_indexed_watermark();
        if (indexed_txid.seqno < to_seqno)
        {
          {
            ccf::View view_of_to_seqno = 0;
            const auto result =
              get_view_for_seqno_v1(to_seqno, view_of_to_seqno);
            if (result == ccf::ApiResult::OK)
            {
              index_per_public_key->extend_index_to(
                {view_of_to_seqno, to_seqno});
            }
          }
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
          static constexpr size_t retry_after_seconds = 3;
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::RETRY_AFTER, retry_after_seconds);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(fmt::format(
            "Still constructing index for public records on key {} - indexed "
            "to {}/{}",
            id,
            indexed_txid.seqno,
            to_seqno));
          return;
        }

        // Set a maximum range, paginate larger requests
        static constexpr size_t max_seqno_per_page = 10000;
        const auto range_begin = from_seqno;
        const auto range_end =
          std::min(to_seqno, range_begin + max_seqno_per_page);

        // SNIPPET_START: indexing_strategy_use
        const auto interesting_seqnos =
          index_per_public_key->get_write_txs_in_range(
            id, range_begin, range_end);
        // SNIPPET_END: indexing_strategy_use
        if (!interesting_seqnos.has_value())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
          static constexpr size_t retry_after_seconds = 3;
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::RETRY_AFTER, retry_after_seconds);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(fmt::format(
            "Still constructing index for private records at {}", id));
          return;
        }

        // Use hash of request as RequestHandle. WARNING: This means identical
        // requests from different users will collide, and overwrite each
        // other's progress!
        auto make_handle = [](size_t begin, size_t end, size_t id) {
          size_t raw[] = {begin, end, id};
          auto size = sizeof(raw);
          std::vector<uint8_t> v(size);
          memcpy(v.data(), reinterpret_cast<const uint8_t*>(raw), size);
          return std::hash<decltype(v)>()(v);
        };

        ccf::historical::RequestHandle handle =
          make_handle(range_begin, range_end, id);

        // Fetch the requested range
        auto& historical_cache = context.get_historical_state();

        std::vector<ccf::kv::ReadOnlyStorePtr> stores;
        if (!interesting_seqnos->empty())
        {
          stores =
            historical_cache.get_stores_for(handle, interesting_seqnos.value());
          if (stores.empty())
          {
            // Empty response indicates these stores are still being fetched.
            // Return a retry response
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
            static constexpr size_t retry_after_seconds = 3;
            ctx.rpc_ctx->set_response_header(
              ccf::http::headers::RETRY_AFTER, retry_after_seconds);
            ctx.rpc_ctx->set_response_header(
              ccf::http::headers::CONTENT_TYPE,
              ccf::http::headervalues::contenttype::TEXT);
            ctx.rpc_ctx->set_response_body(fmt::format(
              "Historical transactions from {} to {} are not yet "
              "available, fetching now",
              range_begin,
              range_end));
            return;
          }
        }
        // else the index authoritatively tells us there are _no_ interesting
        // seqnos in this range, so we have no stores to process, but can return
        // a complete result

        // Process the fetched Stores
        LoggingGetHistoricalRange::Out response;
        for (auto& store : stores)
        {
          auto historical_tx = store->create_read_only_tx();
          auto* records_handle =
            historical_tx.template ro<RecordsMap>(public_records(ctx));
          const auto v = records_handle->get(id);

          if (v.has_value())
          {
            LoggingGetHistoricalRange::Entry e;
            e.seqno = store->get_txid().seqno;
            e.id = id;
            e.msg = v.value();
            response.entries.push_back(e);
          }
          // This response does not include any entry when the given key wasn't
          // modified at this seqno. It could instead indicate that the store
          // was checked with an empty tombstone object, but this approach gives
          // smaller responses
        }

        // If this didn't cover the total requested range, begin fetching the
        // next page and tell the caller how to retrieve it
        if (range_end != to_seqno)
        {
          const auto next_page_start = range_end + 1;
          const auto next_range_end =
            std::min(to_seqno, next_page_start + max_seqno_per_page);
          const auto next_seqnos = index_per_public_key->get_write_txs_in_range(
            id, next_page_start, next_range_end);
          if (next_seqnos.has_value() && !next_seqnos->empty())
          {
            const auto next_page_end = next_seqnos->back();

            ccf::historical::RequestHandle next_page_handle =
              make_handle(next_page_start, next_page_end, id);
            historical_cache.get_store_range(
              next_page_handle, next_page_start, next_page_end);
          }

          // If we don't yet know the next seqnos, or know for sure there are
          // some, then set a next_link
          if (!next_seqnos.has_value() || !next_seqnos->empty())
          {
            // NB: This path tells the caller to continue to ask until the end
            // of the range, even if the next response is paginated
            response.next_link = fmt::format(
              "/app{}?from_seqno={}&to_seqno={}&id={}",
              get_historical_range_path,
              next_page_start,
              to_seqno,
              id);
          }
        }

        // Construct the HTTP response
        ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_OK);
      };
      make_endpoint(
        get_historical_range_path,
        HTTP_GET,
        get_historical_range,
        auth_policies)
        .set_auto_schema<void, LoggingGetHistoricalRange::Out>()
        .add_query_parameter<size_t>(
          "from_seqno", ccf::endpoints::QueryParamPresence::OptionalParameter)
        .add_query_parameter<size_t>(
          "to_seqno", ccf::endpoints::QueryParamPresence::OptionalParameter)
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      static constexpr auto get_historical_sparse_path =
        "/log/private/historical/sparse";
      auto get_historical_sparse = [&, this](
                                     ccf::endpoints::EndpointContext& ctx) {
        // Parse arguments from query
        const auto parsed_query =
          ccf::http::parse_query(ctx.rpc_ctx->get_request_query());

        std::string error_reason;

        size_t id = 0;
        if (!ccf::http::get_query_value(parsed_query, "id", id, error_reason))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidQueryParameterValue,
            std::move(error_reason));
          return;
        }

        std::vector<size_t> seqnos;
        {
          std::string seqnos_s;
          if (!ccf::http::get_query_value(
                parsed_query, "seqnos", seqnos_s, error_reason))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              std::move(error_reason));
            return;
          }

          const auto terms = ccf::nonstd::split(seqnos_s, ",");
          for (const auto& term : terms)
          {
            size_t val = 0;
            const auto [p, ec] = std::from_chars(term.begin(), term.end(), val);
            if (ec != std::errc() || p != term.end())
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidQueryParameterValue,
                fmt::format("Unable to parse '{}' as a seqno", term));
              return;
            }
            seqnos.push_back(val);
          }
        }

        // End of range must be committed

        std::sort(seqnos.begin(), seqnos.end());

        const auto final_seqno = seqnos.back();
        const auto tx_status = get_tx_status(final_seqno);
        if (!tx_status.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Unable to retrieve Tx status");
          return;
        }

        if (tx_status.value() != ccf::TxStatus::Committed)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidInput,
            fmt::format(
              "Only committed transactions can be queried. Transaction at "
              "seqno {} is {}",
              final_seqno,
              ccf::tx_status_to_str(tx_status.value())));
          return;
        }

        // NB: Currently ignoring pagination, as this endpoint is temporary

        // Use hash of request as RequestHandle. WARNING: This means identical
        // requests from different users will collide, and overwrite each
        // other's progress!
        auto make_handle = [](size_t begin, size_t end, size_t id) {
          size_t raw[] = {begin, end, id};
          auto size = sizeof(raw);
          std::vector<uint8_t> v(size);
          memcpy(v.data(), reinterpret_cast<const uint8_t*>(raw), size);
          return std::hash<decltype(v)>()(v);
        };

        ccf::historical::RequestHandle handle = 0;
        {
          std::hash<size_t> h;
          handle = h(id);
          for (const auto& seqno : seqnos)
          {
            ccf::ds::hashutils::hash_combine(handle, seqno, h);
          }
        }

        // Fetch the requested range
        auto& historical_cache = context.get_historical_state();

        ccf::SeqNoCollection seqno_collection(seqnos.begin(), seqnos.end());

        auto stores = historical_cache.get_stores_for(handle, seqno_collection);
        if (stores.empty())
        {
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_ACCEPTED);
          static constexpr size_t retry_after_seconds = 3;
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::RETRY_AFTER, retry_after_seconds);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
          ctx.rpc_ctx->set_response_body(fmt::format(
            "Historical transactions are not yet available, fetching now"));
          return;
        }

        // Process the fetched Stores
        LoggingGetHistoricalRange::Out response;
        for (const auto& store : stores)
        {
          auto historical_tx = store->create_read_only_tx();
          auto* records_handle =
            historical_tx.template ro<RecordsMap>(private_records(ctx));
          const auto v = records_handle->get(id);

          if (v.has_value())
          {
            LoggingGetHistoricalRange::Entry e;
            e.seqno = store->get_txid().seqno;
            e.id = id;
            e.msg = v.value();
            response.entries.push_back(e);
          }
          // This response do not include any entry when the given key wasn't
          // modified at this seqno. It could instead indicate that the store
          // was checked with an empty tombstone object, but this approach gives
          // smaller responses
        }

        // Construct the HTTP response
        ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_OK);
      };
      make_endpoint(
        get_historical_sparse_path,
        HTTP_GET,
        get_historical_sparse,
        auth_policies)
        .set_auto_schema<void, LoggingGetHistoricalRange::Out>()
        .add_query_parameter<std::string>("seqnos")
        .add_query_parameter<size_t>("id")
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto record_admin_only = [this](
                                 ccf::endpoints::EndpointContext& ctx,
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

        auto* view = ctx.tx.template rw<RecordsMap>(private_records(ctx));
        view->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      make_endpoint(
        "/log/private/admin_only",
        HTTP_POST,
        ccf::json_adapter(record_admin_only),
        {ccf::user_cert_auth_policy})
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();

      auto get_request_query = [this](auto& ctx) {
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        std::vector<uint8_t> rq(
          ctx.rpc_ctx->get_request_query().begin(),
          ctx.rpc_ctx->get_request_query().end());
        ctx.rpc_ctx->set_response_body(rq);
      };

      make_endpoint(
        "/log/request_query",
        HTTP_GET,
        get_request_query,
        ccf::no_auth_required)
        .set_auto_schema<void, std::string>()
        .install();

      auto post_cose_signed_content =
        [this](ccf::endpoints::EndpointContext& ctx) {
          const auto& caller_identity =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();

          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::TEXT);
          std::vector<uint8_t> response_body(
            caller_identity.content.begin(), caller_identity.content.end());
          ctx.rpc_ctx->set_response_body(response_body);
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        };

      make_endpoint(
        "/log/cose_signed_content",
        HTTP_POST,
        post_cose_signed_content,
        {ccf::member_cose_sign1_auth_policy})
        .set_auto_schema<void, std::string>()
        .install();

      auto get_cbor_merkle_proof =
        [this](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr historical_state) {
          auto historical_tx = historical_state->store->create_read_only_tx();

          assert(historical_state->receipt);
          auto cbor_proof =
            describe_merkle_proof_v1(*historical_state->receipt);
          if (!cbor_proof.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "No merkle proof available for this transaction");
            return;
          }
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(cbor_proof.value()));
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            ccf::http::headervalues::contenttype::CBOR);
        };
      make_read_only_endpoint(
        "/log/public/cbor_merkle_proof",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_cbor_merkle_proof, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, void>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_cose_endorsements =
        [this](
          ccf::endpoints::ReadOnlyEndpointContext& ctx,
          ccf::historical::StatePtr historical_state) {
          auto historical_tx = historical_state->store->create_read_only_tx();

          assert(historical_state->receipt);
          auto endorsements =
            describe_cose_endorsements_v1(*historical_state->receipt);
          if (!endorsements.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "No COSE endorsements available for this transaction");
            return;
          }
          LoggingGetCoseEndorsements::Out response{
            .endorsements = ccf::SerialisedCoseEndorsements{}};
          for (const auto& endorsement : *endorsements)
          {
            response.endorsements->push_back(endorsement);
          }

          ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_OK);
        };
      make_read_only_endpoint(
        "/log/public/cose_endorsements",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_cose_endorsements, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetCoseEndorsements::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_cose_signature = [this](
                                  ccf::endpoints::ReadOnlyEndpointContext& ctx,
                                  ccf::historical::StatePtr historical_state) {
        auto historical_tx = historical_state->store->create_read_only_tx();

        assert(historical_state->receipt);
        auto signature = describe_cose_signature_v1(*historical_state->receipt);
        if (!signature.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "No COSE signature available for this transaction");
          return;
        }

        LoggingGetCoseSignature::Out response{
          .cose_signature = signature.value()};

        ctx.rpc_ctx->set_response_json(response, HTTP_STATUS_OK);
      };
      make_read_only_endpoint(
        "/log/public/cose_signature",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_cose_signature, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, LoggingGetCoseSignature::Out>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_cose_receipt = [this](
                                ccf::endpoints::ReadOnlyEndpointContext& ctx,
                                ccf::historical::StatePtr historical_state) {
        auto historical_tx = historical_state->store->create_read_only_tx();

        assert(historical_state->receipt);
        auto signature = describe_cose_signature_v1(*historical_state->receipt);
        if (!signature.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "No COSE signature available for this transaction");
          return;
        }
        auto proof = describe_merkle_proof_v1(*historical_state->receipt);
        if (!proof.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "No merkle proof available for this transaction");
          return;
        }

        constexpr int64_t vdp = 396;
        auto inclusion_proof = ccf::cose::edit::pos::AtKey{-1};

        ccf::cose::edit::desc::Value desc{inclusion_proof, vdp, *proof};

        auto cose_receipt =
          ccf::cose::edit::set_unprotected_header(*signature, desc);

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          ccf::http::headervalues::contenttype::COSE);
        ctx.rpc_ctx->set_response_body(cose_receipt);
      };
      make_read_only_endpoint(
        "/log/public/cose_receipt",
        HTTP_GET,
        ccf::historical::read_only_adapter_v4(
          get_cose_receipt, context, is_tx_committed),
        auth_policies)
        .set_auto_schema<void, void>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();

      auto get_cose_signatures_config =
        [&](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          auto subsystem =
            context.get_subsystem<ccf::cose::AbstractCOSESignaturesConfig>();
          if (!subsystem)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "COSE signatures subsystem not available");
            return;
          }
          auto config = subsystem->get_cose_signatures_config();

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(nlohmann::json(config).dump());
        };

      make_read_only_endpoint(
        "/cose_signatures_config",
        HTTP_GET,
        get_cose_signatures_config,
        auth_policies)
        .set_auto_schema<void, void>()
        .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
        .install();
    }
  };
}

namespace ccf
{
  // SNIPPET_START: app_interface
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<loggingapp::LoggerHandlers>(context);
  }
  // SNIPPET_END: app_interface
}
