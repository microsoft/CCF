// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "logging_schema.h"
#include "node/rpc/userfrontend.h"

#include <fmt/format_header_only.h>
#include <valijson/adapters/nlohmann_json_adapter.hpp>
#include <valijson/schema.hpp>
#include <valijson/schema_parser.hpp>
#include <valijson/validator.hpp>

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace fmt
{
  template <>
  struct formatter<valijson::ValidationResults::Error>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const valijson::ValidationResults::Error& e, FormatContext& ctx)
    {
      return format_to(
        ctx.begin(), "[{}] {}", fmt::join(e.context, ""), e.description);
    }
  };

  template <>
  struct formatter<valijson::ValidationResults>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const valijson::ValidationResults& vr, FormatContext& ctx)
    {
      return format_to(ctx.begin(), "{}", fmt::join(vr, "\n\t"));
    }
  };
}

namespace ccfapp
{
  struct Procs
  {
    static constexpr auto LOG_RECORD = "LOG_record";
    static constexpr auto LOG_GET = "LOG_get";

    static constexpr auto LOG_RECORD_PUBLIC = "LOG_record_pub";
    static constexpr auto LOG_GET_PUBLIC = "LOG_get_pub";
  };

  // SNIPPET_START: errors
  enum class LoggerErrors : jsonrpc::ErrorBaseType
  {
    UNKNOWN_ID =
      (jsonrpc::ErrorBaseType)jsonrpc::CCFErrorCodes::APP_ERROR_START - 1,
    MESSAGE_EMPTY = UNKNOWN_ID - 1,
  };

  std::string get_error_prefix(LoggerErrors ec)
  {
    std::stringstream ss;
    ss << "[";
    switch (ec)
    {
      case (LoggerErrors::UNKNOWN_ID):
      {
        ss << "UNKNOWN_ID";
        break;
      }
      case (LoggerErrors::MESSAGE_EMPTY):
      {
        ss << "MESSAGE_EMPTY";
        break;
      }
      default:
      {
        ss << "UNKNOWN LOGGER ERROR";
        break;
      }
    }
    ss << "]: ";
    return ss.str();
  }
  // SNIPPET_END: errors

  // SNIPPET: table_definition
  using Table = Store::Map<size_t, string>;

  // SNIPPET: inherit_frontend
  class LoggerHandlers : public UserHandlerRegistry
  {
  private:
    Table& records;
    Table& public_records;

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
    LoggerHandlers(NetworkTables& nwt, AbstractNotifier& notifier) :
      UserHandlerRegistry(nwt),
      records(
        nwt.tables->create<Table>("records", kv::SecurityDomain::PRIVATE)),
      public_records(nwt.tables->create<Table>(
        "public_records", kv::SecurityDomain::PUBLIC)),
      // SNIPPET_END: constructor
      record_public_params_schema(nlohmann::json::parse(j_record_public_in)),
      record_public_result_schema(nlohmann::json::parse(j_record_public_out)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      // SNIPPET_START: record
      // SNIPPET_START: macro_validation_record
      auto record = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto in = params.get<LoggingRecord::In>();
        // SNIPPET_END: macro_validation_record

        if (in.msg.empty())
        {
          return make_error(
            LoggerErrors::MESSAGE_EMPTY, "Cannot record an empty log message");
        }

        auto view = tx.get_view(records);
        view->put(in.id, in.msg);
        return make_success(true);
      };
      // SNIPPET_END: record

      // SNIPPET_START: get
      auto get = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto in = params.get<LoggingGet::In>();
        auto view = tx.get_view(records);
        auto r = view->get(in.id);

        if (r.has_value())
          return make_success(LoggingGet::Out{r.value()});

        return make_error(
          LoggerErrors::UNKNOWN_ID, fmt::format("No such record: {}", in.id));
      };
      // SNIPPET_END: get

      // SNIPPET_START: record_public
      // SNIPPET_START: valijson_record_public
      auto record_public = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto validation_error =
          validate(params, record_public_params_schema);

        if (validation_error.has_value())
        {
          return make_error(
            jsonrpc::StandardErrorCodes::PARSE_ERROR, *validation_error);
        }
        // SNIPPET_END: valijson_record_public

        const auto msg = params["msg"].get<std::string>();
        if (msg.empty())
        {
          return make_error(
            LoggerErrors::MESSAGE_EMPTY, "Cannot record an empty log message");
        }

        auto view = tx.get_view(public_records);
        view->put(params["id"], msg);
        return make_success(true);
      };
      // SNIPPET_END: record_public

      // SNIPPET_START: get_public
      auto get_public = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto validation_error =
          validate(params, get_public_params_schema);

        if (validation_error.has_value())
        {
          return make_error(
            jsonrpc::StandardErrorCodes::PARSE_ERROR, *validation_error);
        }

        auto view = tx.get_view(public_records);
        const auto id = params["id"];
        auto r = view->get(id);

        if (r.has_value())
        {
          auto result = nlohmann::json::object();
          result["msg"] = r.value();
          return make_success(result);
        }

        return make_error(
          LoggerErrors::UNKNOWN_ID,
          fmt::format("No such record: {}", id.dump()));
      };
      // SNIPPET_END: get_public

      install_with_auto_schema<LoggingRecord::In, bool>(
        Procs::LOG_RECORD, handler_adapter(record), Write);
      // SNIPPET: install_get
      install_with_auto_schema<LoggingGet>(
        Procs::LOG_GET, handler_adapter(get), Read);

      install(
        Procs::LOG_RECORD_PUBLIC,
        handler_adapter(record_public),
        Write,
        record_public_params_schema,
        record_public_result_schema);
      install(
        Procs::LOG_GET_PUBLIC,
        handler_adapter(get_public),
        Read,
        get_public_params_schema,
        get_public_result_schema);

      nwt.signatures.set_global_hook([this, &notifier](
                                       kv::Version version,
                                       const Signatures::State& s,
                                       const Signatures::Write& w) {
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
    Logger(NetworkTables& network, AbstractNotifier& notifier) :
      ccf::UserRpcFrontend(*network.tables, logger_handlers),
      logger_handlers(network, notifier)
    {}
  };

  // SNIPPET_START: rpc_handler
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return make_shared<Logger>(nwt, notifier);
  }
  // SNIPPET_END: rpc_handler
}
