// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "node/entities.h"
#include "node/rpc/nodeinterface.h"
#include "node/rpc/userfrontend.h"

using namespace std;
using namespace nlohmann;
using namespace ccf;

namespace ccfapp
{
  struct Procs
  {
    static constexpr auto LOG_RECORD = "LOG_record";
    static constexpr auto LOG_RECORD_PUBLIC = "LOG_record_pub";
    static constexpr auto LOG_GET = "LOG_get";
    static constexpr auto LOG_GET_PUBLIC = "LOG_get_pub";
  };

  // SNIPPET: table_definition
  using Table = Store::Map<size_t, string>;

  class Logger : public ccf::UserRpcFrontend
  {
  private:
    Table& records;
    Table& public_records;

  public:
    Logger(NetworkTables& nwt, AbstractNotifier& notifier) :
      UserRpcFrontend(*nwt.tables),
      records(tables.create<Table>(ccf::Tables::APP)),
      public_records(tables.create<Table>(
        ccf::Tables::APP_PUBLIC, kv::SecurityDomain::PUBLIC))
    {
      // SNIPPET_START: record
      auto record = [this](Store::Tx& tx, const nlohmann::json& params) {
        auto view = tx.get_view(records);
        view->put(params["id"], params["msg"]);
        return jsonrpc::success();
      };
      // SNIPPET_END: record

      // SNIPPET_START: get
      auto get = [this](Store::Tx& tx, const nlohmann::json& params) {
        auto view = tx.get_view(records);
        auto r = view->get(params["id"]);

        if (r.has_value())
          return jsonrpc::success(r.value());

        return jsonrpc::error(
          jsonrpc::ErrorCodes::INVALID_PARAMS, "No such record");
      };
      // SNIPPET_END: get

      // SNIPPET_START: record_public
      auto record_public = [this](Store::Tx& tx, const nlohmann::json& params) {
        auto view = tx.get_view(public_records);
        view->put(params["id"], params["msg"]);
        return jsonrpc::success();
      };
      // SNIPPET_END: record_public

      // SNIPPET_START: get_public
      auto get_public = [this](Store::Tx& tx, const nlohmann::json& params) {
        auto view = tx.get_view(public_records);
        auto r = view->get(params["id"]);

        if (r.has_value())
          return jsonrpc::success(r.value());

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
