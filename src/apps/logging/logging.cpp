// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "logging_schema.h"
#include "node/entities.h"
#include "node/rpc/nodeinterface.h"
#include "node/rpc/userfrontend.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
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

  // SNIPPET: table_definition
  using Table = Store::Map<size_t, string>;

  class Logger : public ccf::UserRpcFrontend
  {
  private:
    Table& records;
    Table& public_records;

    const nlohmann::json record_public_params_schema;

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
    Logger(NetworkTables& nwt, AbstractNotifier& notifier) :
      UserRpcFrontend(*nwt.tables),
      records(tables.create<Table>(ccf::Tables::APP)),
      public_records(tables.create<Table>(
        ccf::Tables::APP_PUBLIC, kv::SecurityDomain::PUBLIC)),
      record_public_params_schema(nlohmann::json::parse(j_record_public)),
      get_public_params_schema(nlohmann::json::parse(j_get_public_in)),
      get_public_result_schema(nlohmann::json::parse(j_get_public_out))
    {
      // SNIPPET_START: record
      // SNIPPET_START: macro_validation_record
      register_auto_schema<LoggingRecord::In, void>(Procs::LOG_RECORD);
      auto record = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto in = params.get<LoggingRecord::In>();
        // SNIPPET_END: macro_validation_record
        auto view = tx.get_view(records);
        view->put(in.id, in.msg);
        return jsonrpc::success();
      };
      // SNIPPET_END: record

      // SNIPPET_START: get
      register_auto_schema<LoggingGet>(Procs::LOG_GET);
      auto get = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto in = params.get<LoggingGet::In>();
        auto view = tx.get_view(records);
        auto r = view->get(in.id);

        if (r.has_value())
          return jsonrpc::success(LoggingGet::Out{r.value()});

        return jsonrpc::error(
          jsonrpc::ErrorCodes::INVALID_PARAMS, "No such record");
      };
      // SNIPPET_END: get

      // SNIPPET_START: record_public
      // SNIPPET_START: valijson_record_public
      register_schema(
        Procs::LOG_RECORD_PUBLIC,
        record_public_params_schema,
        nlohmann::json::object());
      auto record_public = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto validation_error =
          validate(params, record_public_params_schema);

        if (validation_error.has_value())
        {
          return jsonrpc::error(
            jsonrpc::ErrorCodes::PARSE_ERROR, *validation_error);
        }
        // SNIPPET_END: valijson_record_public

        auto view = tx.get_view(public_records);
        view->put(params["id"], params["msg"]);
        return jsonrpc::success();
      };
      // SNIPPET_END: record_public

      // SNIPPET_START: get_public
      register_schema(
        Procs::LOG_GET_PUBLIC,
        get_public_params_schema,
        get_public_result_schema);
      auto get_public = [this](Store::Tx& tx, const nlohmann::json& params) {
        const auto validation_error =
          validate(params, get_public_params_schema);

        if (validation_error.has_value())
        {
          return jsonrpc::error(
            jsonrpc::ErrorCodes::PARSE_ERROR, *validation_error);
        }

        auto view = tx.get_view(public_records);
        auto r = view->get(params["id"]);

        if (r.has_value())
        {
          auto result = nlohmann::json::object();
          result["msg"] = r.value();
          return jsonrpc::success(result);
        }

        return jsonrpc::error(
          jsonrpc::ErrorCodes::INVALID_PARAMS, "No such record");
      };
      // SNIPPET_END: get_public

      // SNIPPET: install_record
      install(Procs::LOG_RECORD, record, Write);
      install(Procs::LOG_GET, get, Read);

      install(Procs::LOG_RECORD_PUBLIC, record_public, Write);
      install(Procs::LOG_GET_PUBLIC, get_public, Read);

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

  // SNIPPET_START: rpc_handler
  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return make_shared<Logger>(nwt, notifier);
  }
  // SNIPPET_END: rpc_handler
}
