// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "handler_registry.h"
#include "json_handler.h"
#include "metrics.h"

namespace ccf
{
  /*
   * Extends the basic HandlerRegistry with methods which should be present
   * on all frontends
   */
  class CommonHandlerRegistry : public HandlerRegistry
  {
  private:
    metrics::Metrics metrics;

    Nodes* nodes = nullptr;

  protected:
    kv::Store* tables = nullptr;

  public:
    CommonHandlerRegistry(
      kv::Store& store, const std::string& certs_table_name = "") :
      HandlerRegistry(store, certs_table_name),
      nodes(store.get<Nodes>(Tables::NODES)),
      tables(&store)
    {}

    void init_handlers(kv::Store& t) override
    {
      HandlerRegistry::init_handlers(t);

      auto get_commit = [this](kv::Tx& tx, nlohmann::json&& params) {
        if (consensus != nullptr)
        {
          auto [view, seqno] = consensus->get_committed_txid();
          return make_success(GetCommit::Out{view, seqno});
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          "Failed to get commit info from Consensus");
      };
      make_handler("commit", HTTP_GET, json_adapter(get_commit))
        .set_execute_locally(true)
        .set_auto_schema<void, GetCommit::Out>()
        .install();

      auto get_tx_status = [this](kv::Tx& tx, nlohmann::json&& params) {
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
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Consensus is not yet configured");
      };
      make_handler("tx", HTTP_GET, json_adapter(get_tx_status))
        .set_auto_schema<GetTxStatus>()
        .install();

      auto get_metrics = [this](kv::Tx& tx, nlohmann::json&& params) {
        auto result = metrics.get_metrics();
        return make_success(result);
      };
      make_handler("metrics", HTTP_GET, json_adapter(get_metrics))
        .set_auto_schema<void, GetMetrics::Out>()
        .set_execute_locally(true)
        .install();

      auto make_signature = [this](kv::Tx& tx, nlohmann::json&& params) {
        if (consensus != nullptr)
        {
          if (consensus->type() == ConsensusType::RAFT)
          {
            if (history != nullptr)
            {
              history->emit_signature();
              return make_success(true);
            }
          }
          else if (consensus->type() == ConsensusType::PBFT)
          {
            consensus->emit_signature();
            return make_success(true);
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Failed to trigger signature");
      };
      make_handler("mkSign", HTTP_POST, json_adapter(make_signature))
        .set_auto_schema<void, bool>()
        .install();

      if (certs != nullptr)
      {
        auto who =
          [this](kv::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
            if (certs == nullptr)
            {
              return make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                "This frontend does not support 'who'");
            }

            if (!params.is_null())
            {
              const WhoIs::In in = params;
              auto certs_view = tx.get_view(*certs);
              auto caller_id_opt = certs_view->get(in.cert);

              if (!caller_id_opt.has_value())
              {
                return make_error(
                  HTTP_STATUS_BAD_REQUEST, "Certificate not recognised");
              }

              caller_id = caller_id_opt.value();
            }

            return make_success(WhoAmI::Out{caller_id});
          };
        make_handler("who", HTTP_GET, json_adapter(who))
          .set_auto_schema<WhoIs::In, WhoAmI::Out>()
          .install();
      }

      auto get_primary_info = [this](kv::Tx& tx, nlohmann::json&& params) {
        if ((nodes != nullptr) && (consensus != nullptr))
        {
          NodeId primary_id = consensus->primary();
          auto current_view = consensus->get_view();

          auto nodes_view = tx.get_view(*nodes);
          auto info = nodes_view->get(primary_id);

          if (info)
          {
            GetPrimaryInfo::Out out;
            out.primary_id = primary_id;
            out.primary_host = info->pubhost;
            out.primary_port = info->rpcport;
            out.current_view = current_view;
            return make_success(out);
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Primary unknown.");
      };
      make_handler("primary_info", HTTP_GET, json_adapter(get_primary_info))
        .set_auto_schema<void, GetPrimaryInfo::Out>()
        .install();

      auto get_network_info = [this](kv::Tx& tx, nlohmann::json&& params) {
        GetNetworkInfo::Out out;
        if (consensus != nullptr)
        {
          out.primary_id = consensus->primary();
        }

        auto nodes_view = tx.get_view(*nodes);
        nodes_view->foreach([&out](const NodeId& nid, const NodeInfo& ni) {
          if (ni.status == ccf::NodeStatus::TRUSTED)
          {
            out.nodes.push_back({nid, ni.pubhost, ni.rpcport});
          }
          return true;
        });

        return make_success(out);
      };
      make_handler("network_info", HTTP_GET, json_adapter(get_network_info))
        .set_auto_schema<void, GetNetworkInfo::Out>()
        .install();

      auto list_methods_fn = [this](kv::Tx& tx, nlohmann::json&& params) {
        ListMethods::Out out;

        list_methods(tx, out);

        std::sort(out.methods.begin(), out.methods.end());

        return make_success(out);
      };
      make_handler("api", HTTP_GET, json_adapter(list_methods_fn))
        .set_auto_schema<void, ListMethods::Out>()
        .install();

      auto get_schema = [this](RequestArgs& args, nlohmann::json&& params) {
        const auto in = params.get<GetSchema::In>();

        const auto it = installed_handlers.find(in.method);
        if (it == installed_handlers.end())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format("Method {} not recognised", in.method));
        }

        auto j = nlohmann::json::object();

        for (auto& [verb, handler] : it->second)
        {
          std::string verb_name = http_method_str(verb);
          std::transform(
            verb_name.begin(),
            verb_name.end(),
            verb_name.begin(),
            [](unsigned char c) { return std::tolower(c); });
          j[verb_name] =
            GetSchema::Out{handler.params_schema, handler.result_schema};
        }

        return make_success(j);
      };
      make_handler("api/schema", HTTP_GET, json_adapter(get_schema))
        .set_auto_schema<GetSchema>()
        .install();

      auto get_receipt = [this](kv::Tx& tx, nlohmann::json&& params) {
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
              fmt::format(
                "Unable to produce receipt for commit {} : {}",
                in.commit,
                e.what()));
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Unable to produce receipt");
      };
      make_handler("receipt", HTTP_GET, json_adapter(get_receipt))
        .set_auto_schema<GetReceipt>()
        .install();

      auto verify_receipt = [this](kv::Tx& tx, nlohmann::json&& params) {
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
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              fmt::format("Unable to verify receipt: {}", e.what()));
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Unable to verify receipt");
      };
      make_handler("receipt/verify", HTTP_POST, json_adapter(verify_receipt))
        .set_read_write(ReadWrite::Read)
        .set_auto_schema<VerifyReceipt>()
        .install();
    }

    void tick(
      std::chrono::milliseconds elapsed,
      kv::Consensus::Statistics stats) override
    {
      metrics.track_tx_rates(elapsed, stats);

      HandlerRegistry::tick(elapsed, stats);
    }
  };
}