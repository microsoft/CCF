// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "formatters.h"
#include "logging_schema.h"
#include "node/quote.h"
#include "node/rpc/user_frontend.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

using namespace std;
using namespace nlohmann;

namespace loggingapp
{
  struct Procs
  {
    static constexpr auto LOG_RECORD = "LOG_record";
    static constexpr auto LOG_GET = "LOG_get";

    static constexpr auto LOG_RECORD_PUBLIC = "LOG_record_pub";
    static constexpr auto LOG_GET_PUBLIC = "LOG_get_pub";

    static constexpr auto LOG_RECORD_PREFIX_CERT = "LOG_record_prefix_cert";
    static constexpr auto LOG_RECORD_ANONYMOUS_CALLER = "LOG_record_anonymous";
    static constexpr auto LOG_RECORD_RAW_TEXT = "LOG_record_raw_text";
    static constexpr auto LOG_GET_HISTORICAL = "LOG_get_historical";
  };

  // SNIPPET: table_definition
  using Table = kv::Map<size_t, string>;

  // SNIPPET: inherit_frontend
  class LoggerHandlers : public ccf::UserHandlerRegistry
  {
  private:
    Table& records;
    Table& public_records;
    ccf::CodeIDs& user_code_ids;

    const nlohmann::json record_public_params_schema;
    const nlohmann::json record_public_result_schema;

    const nlohmann::json get_public_params_schema;
    const nlohmann::json get_public_result_schema;

    std::optional<std::string> validate(
      const nlohmann::json& params, const nlohmann::json& j_schema)
    {
      valijson::Schema schema;
      valijson::SchemaParser parser;
      valijson::adapters::NlohmannJsonAdapter schema_adapter(j_schema);
      parser.populateSchema(schema_adapter, schema);

      valijson::Validator validator;
      valijson::ValidationResults results;
      valijson::adapters::NlohmannJsonAdapter params_adapter(params);

      if (!validator.validate(schema, params_adapter, &results))
      {
        return fmt::format("Error during validation:\n\t{}", results);
      }

      return std::nullopt;
    }

  public:
    // SNIPPET_START: constructor
    LoggerHandlers(
      ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) :
      UserHandlerRegistry(nwt),
      records(
        nwt.tables->create<Table>("records", kv::SecurityDomain::PRIVATE)),
      public_records(nwt.tables->create<Table>(
        "public_records", kv::SecurityDomain::PUBLIC)),
      // SNIPPET_END: constructor
      user_code_ids(*nwt.tables->get<ccf::CodeIDs>(ccf::Tables::USER_CODE_IDS)),
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      // SNIPPET_START: record
      // SNIPPET_START: macro_validation_record
      auto record = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingRecord::In>();
        // SNIPPET_END: macro_validation_record

        if (in.msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, "Cannot record an empty log message");
        }

        auto view = tx.get_view(records);
        view->put(in.id, in.msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: get
      auto get = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<LoggingGet::In>();
        auto view = tx.get_view(records);
        auto r = view->get(in.id);

        if (r.has_value())
          return ccf::make_success(LoggingGet::Out{r.value()});

        return ccf::make_error(
          HTTP_STATUS_BAD_REQUEST, fmt::format("No such record: {}", in.id));
      };
      // SNIPPET_END: get

      // SNIPPET_START: record_public
      // SNIPPET_START: valijson_record_public
      auto record_public = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto validation_error =
          validate(params, record_public_params_schema);

        if (validation_error.has_value())
        {
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, *validation_error);
        }
        // SNIPPET_END: valijson_record_public

        const auto msg = params["msg"].get<std::string>();
        if (msg.empty())
        {
          return ccf::make_error(
            HTTP_STATUS_BAD_REQUEST, "Cannot record an empty log message");
        }

        auto view = tx.get_view(public_records);
        view->put(params["id"], msg);
        return ccf::make_success(true);
      };
      // SNIPPET_END: record_public

      // SNIPPET_START: get_public
      auto get_public = [this](kv::Tx& tx, nlohmann::json&& params) {
        const auto validation_error =
          validate(params, get_public_params_schema);

        if (validation_error.has_value())
        {
          return ccf::make_error(HTTP_STATUS_BAD_REQUEST, *validation_error);
        }

        auto view = tx.get_view(public_records);
        const auto id = params["id"];
        auto r = view->get(id);

        if (r.has_value())
        {
          auto result = nlohmann::json::object();
          result["msg"] = r.value();
          return ccf::make_success(result);
        }

        return ccf::make_error(
          HTTP_STATUS_BAD_REQUEST,
          fmt::format("No such record: {}", id.dump()));
      };
      // SNIPPET_END: get_public

      // SNIPPET_START: log_record_prefix_cert
      auto log_record_prefix_cert = [this](ccf::RequestArgs& args) {
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

        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);

        const auto& cert_data = args.rpc_ctx->session->caller_cert;
        const auto ret =
          mbedtls_x509_crt_parse(&cert, cert_data.data(), cert_data.size());

        const auto log_line = fmt::format("{}: {}", cert.subject, in.msg);
        auto view = args.tx.get_view(records);
        view->put(in.id, log_line);

        mbedtls_x509_crt_free(&cert);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(true).dump());
      };
      // SNIPPET_END: log_record_prefix_cert

      auto log_record_anonymous =
        [this](ccf::RequestArgs& args, nlohmann::json&& params) {
          const auto in = params.get<LoggingRecord::In>();
          if (in.msg.empty())
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST, "Cannot record an empty log message");
          }

          const auto log_line = fmt::format("Anonymous: {}", in.msg);
          auto view = args.tx.get_view(records);
          view->put(in.id, log_line);
          return ccf::make_success(true);
        };

      // SNIPPET_START: log_record_text
      auto log_record_text = [this](ccf::RequestArgs& args) {
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

        constexpr auto log_id_header = "x-log-id";
        const auto id_it = args.rpc_ctx->get_request_header(log_id_header);
        if (!id_it.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            fmt::format("Missing ID header '{}'", log_id_header));
          return;
        }

        const auto id = strtoul(id_it.value().c_str(), nullptr, 10);

        const std::vector<uint8_t>& content = args.rpc_ctx->get_request_body();
        const std::string log_line(content.begin(), content.end());

        auto view = args.tx.get_view(records);
        view->put(id, log_line);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };
      // SNIPPET_END: log_record_text

      auto get_historical = [this](
                              ccf::RequestArgs& args,
                              ccf::historical::StorePtr historical_store,
                              kv::Consensus::View historical_view,
                              kv::Consensus::SeqNo historical_seqno) {
        const auto [pack, params] =
          ccf::jsonhandler::get_json_params(args.rpc_ctx);

        auto* historical_map = historical_store->get(records);
        if (historical_map == nullptr)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(fmt::format(
            "Unable to get table '{}' at {}.{}",
            records.get_name(),
            historical_view,
            historical_seqno));
          return;
        }

        const auto in = params.get<LoggingGetHistorical::In>();

        kv::Tx historical_tx;
        auto view = historical_tx.get_view(*historical_map);
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

      make_handler(Procs::LOG_RECORD, HTTP_POST, ccf::json_adapter(record))
        .set_auto_schema<LoggingRecord::In, bool>()
        .install();
      // SNIPPET_START: install_get
      make_handler(Procs::LOG_GET, HTTP_GET, ccf::json_adapter(get))
        .set_auto_schema<LoggingGet>()
        .install();
      // SNIPPET_END: install_get

      make_handler(
        Procs::LOG_RECORD_PUBLIC, HTTP_POST, ccf::json_adapter(record_public))
        .set_params_schema(record_public_params_schema)
        .set_result_schema(record_public_result_schema)
        .install();
      make_handler(
        Procs::LOG_GET_PUBLIC, HTTP_GET, ccf::json_adapter(get_public))
        .set_params_schema(get_public_params_schema)
        .set_result_schema(get_public_result_schema)
        .install();

      make_handler(
        Procs::LOG_RECORD_PREFIX_CERT, HTTP_POST, log_record_prefix_cert)
        .install();
      make_handler(
        Procs::LOG_RECORD_ANONYMOUS_CALLER,
        HTTP_POST,
        ccf::json_adapter(log_record_anonymous))
        .set_auto_schema<LoggingRecord::In, bool>()
        .set_require_client_identity(false)
        .install();
      make_handler(Procs::LOG_RECORD_RAW_TEXT, HTTP_POST, log_record_text)
        .install();
      make_handler(
        Procs::LOG_GET_HISTORICAL,
        HTTP_GET,
        ccf::historical::adapter(
          get_historical, context.get_historical_state(), is_tx_committed))
        .install();

      auto& notifier = context.get_notifier();
      nwt.signatures.set_global_hook(
        [this,
         &notifier](kv::Version version, const ccf::Signatures::Write& w) {
          if (w.size() > 0)
          {
            nlohmann::json notify_j;
            notify_j["commit"] = version;
            notifier.notify(jsonrpc::pack(notify_j, jsonrpc::Pack::Text));
          }
        });
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
