// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consts.h"
#include "handlerregistry.h"
#include "jsonhandler.h"
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
    Store* tables = nullptr;

  public:
    CommonHandlerRegistry(
      Store& store, const std::string& certs_table_name = "") :
      HandlerRegistry(store, certs_table_name),
      nodes(store.get<Nodes>(Tables::NODES)),
      tables(&store)
    {}

    void init_handlers(Store& t) override
    {
      HandlerRegistry::init_handlers(t);

      auto get_commit = [this](Store::Tx& tx, nlohmann::json&& params) {
        GetCommit::In in{};
        if (!params.is_null())
        {
          in = params.get<GetCommit::In>();
        }

        kv::Version commit = in.commit.value_or(tables->commit_version());

        if (consensus != nullptr)
        {
          auto term = consensus->get_view(commit);
          return make_success(GetCommit::Out{term, commit});
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          "Failed to get commit info from Consensus");
      };

      auto get_metrics = [this](Store::Tx& tx, nlohmann::json&& params) {
        auto result = metrics.get_metrics();
        return make_success(result);
      };

      auto make_signature = [this](Store::Tx& tx, nlohmann::json&& params) {
        if (consensus != nullptr)
        {
          if (consensus->type() == ConsensusType::Raft)
          {
            if (history != nullptr)
            {
              history->emit_signature();
              return make_success(true);
            }
          }
          else if (consensus->type() == ConsensusType::Pbft)
          {
            consensus->emit_signature();
            return make_success(true);
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Failed to trigger signature");
      };

      auto who_am_i =
        [this](
          Store::Tx& tx, CallerId caller_id, const nlohmann::json& params) {
          if (certs == nullptr)
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              fmt::format(
                "This frontend does not support {}", GeneralProcs::WHO_AM_I));
          }

          return make_success(WhoAmI::Out{caller_id});
        };

      auto who_is = [this](Store::Tx& tx, nlohmann::json&& params) {
        const WhoIs::In in = params;

        if (certs == nullptr)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            fmt::format(
              "This frontend does not support {}", GeneralProcs::WHO_IS));
        }
        auto certs_view = tx.get_view(*certs);
        auto caller_id = certs_view->get(in.cert);

        if (!caller_id.has_value())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Certificate not recognised");
        }

        return make_success(WhoIs::Out{caller_id.value()});
      };

      auto get_primary_info = [this](Store::Tx& tx, nlohmann::json&& params) {
        if ((nodes != nullptr) && (consensus != nullptr))
        {
          NodeId primary_id = consensus->primary();

          auto nodes_view = tx.get_view(*nodes);
          auto info = nodes_view->get(primary_id);

          if (info)
          {
            GetPrimaryInfo::Out out;
            out.primary_id = primary_id;
            out.primary_host = info->pubhost;
            out.primary_port = info->rpcport;
            return make_success(out);
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Primary unknown.");
      };

      auto get_network_info = [this](Store::Tx& tx, nlohmann::json&& params) {
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

      auto list_methods_fn = [this](Store::Tx& tx, nlohmann::json&& params) {
        ListMethods::Out out;

        list_methods(tx, out);

        std::sort(out.methods.begin(), out.methods.end());

        return make_success(out);
      };

      auto get_schema = [this](Store::Tx& tx, nlohmann::json&& params) {
        const auto in = params.get<GetSchema::In>();

        const auto it = handlers.find(in.method);
        if (it == handlers.end())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format("Method {} not recognised", in.method));
        }

        const GetSchema::Out out{it->second.params_schema,
                                 it->second.result_schema};

        return make_success(out);
      };

      auto get_receipt = [this](Store::Tx& tx, nlohmann::json&& params) {
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

      auto verify_receipt = [this](Store::Tx& tx, nlohmann::json&& params) {
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

      install_with_auto_schema<GetCommit>(
        GeneralProcs::GET_COMMIT, json_adapter(get_commit), Read);
      install_with_auto_schema<void, GetMetrics::Out>(
        GeneralProcs::GET_METRICS,
        json_adapter(get_metrics),
        Read,
        false, // does not require client signature
        true); // executed locally
      install_with_auto_schema<void, bool>(
        GeneralProcs::MK_SIGN, json_adapter(make_signature), Write);
      install_with_auto_schema<void, WhoAmI::Out>(
        GeneralProcs::WHO_AM_I, json_adapter(who_am_i), Read);
      install_with_auto_schema<WhoIs::In, WhoIs::Out>(
        GeneralProcs::WHO_IS, json_adapter(who_is), Read);
      install_with_auto_schema<void, GetPrimaryInfo::Out>(
        GeneralProcs::GET_PRIMARY_INFO, json_adapter(get_primary_info), Read);
      install_with_auto_schema<void, GetNetworkInfo::Out>(
        GeneralProcs::GET_NETWORK_INFO, json_adapter(get_network_info), Read);
      install_with_auto_schema<void, ListMethods::Out>(
        GeneralProcs::LIST_METHODS, json_adapter(list_methods_fn), Read);
      install_with_auto_schema<GetSchema>(
        GeneralProcs::GET_SCHEMA, json_adapter(get_schema), Read);
      install_with_auto_schema<GetReceipt>(
        GeneralProcs::GET_RECEIPT, json_adapter(get_receipt), Read);
      install_with_auto_schema<VerifyReceipt>(
        GeneralProcs::VERIFY_RECEIPT, json_adapter(verify_receipt), Read);
    }

    void tick(std::chrono::milliseconds elapsed, size_t tx_count) override
    {
      metrics.track_tx_rates(elapsed, tx_count);

      HandlerRegistry::tick(elapsed, tx_count);
    }
  };
}