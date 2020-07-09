// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "endpoint_registry.h"
#include "http/http_consts.h"
#include "http/ws_consts.h"
#include "json_handler.h"
#include "metrics.h"
#include "node/code_id.h"

#include <charconv>

namespace ccf
{
  /*
   * Extends the basic EndpointRegistry with methods which should be present
   * on all frontends
   */
  class CommonEndpointRegistry : public EndpointRegistry
  {
  private:
    metrics::Metrics metrics;
    Nodes* nodes = nullptr;
    CodeIDs* node_code_ids = nullptr;

  protected:
    kv::Store* tables = nullptr;

    bool get_tx_id_from_path(
      const enclave::PathParams& params, kv::TxID& tx_id, std::string& error)
    {
      kv::Consensus::View view;
      {
        const auto view_it = params.find("view");
        if (view_it == params.end())
        {
          error = fmt::format("No parameter named 'view' in path");
          return false;
        }

        const auto view_s = view_it->second;
        const auto [p, ec] =
          std::from_chars(view_s.data(), view_s.data() + view_s.size(), view);
        if (ec != std::errc())
        {
          error = fmt::format(
            "Unable to parse path parameter '{}' as a view", view_s);
          return false;
        }
      }

      kv::Consensus::SeqNo seqno;
      {
        const auto seqno_it = params.find("seqno");
        if (seqno_it == params.end())
        {
          error = fmt::format("No parameter named 'seqno' in path");
          return false;
        }

        const auto seqno_s = seqno_it->second;
        const auto [p, ec] = std::from_chars(
          seqno_s.data(), seqno_s.data() + seqno_s.size(), seqno);
        if (ec != std::errc())
        {
          error = fmt::format(
            "Unable to parse path parameter '{}' as a seqno", seqno_s);
          return false;
        }
      }

      tx_id.term = view;
      tx_id.version = seqno;
      return true;
    }

  public:
    CommonEndpointRegistry(
      kv::Store& store, const std::string& certs_table_name = "") :
      EndpointRegistry(store, certs_table_name),
      nodes(store.get<Nodes>(Tables::NODES)),
      node_code_ids(store.get<CodeIDs>(Tables::NODE_CODE_IDS)),
      tables(&store)
    {}

    void init_handlers(kv::Store& t) override
    {
      EndpointRegistry::init_handlers(t);

      auto get_commit = [this](auto& args, nlohmann::json&& params) {
        if (consensus != nullptr)
        {
          auto [view, seqno] = consensus->get_committed_txid();
          return make_success(GetCommit::Out{view, seqno});
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          "Failed to get commit info from Consensus");
      };
      make_command_endpoint(
        "commit", HTTP_GET, json_command_adapter(get_commit))
        .set_execute_locally(true)
        .set_auto_schema<void, GetCommit::Out>()
        .install();

      auto get_tx_status = [this](auto& args, nlohmann::json&& params) {
        kv::TxID tx_id;
        std::string error;
        if (!get_tx_id_from_path(
              args.rpc_ctx->get_request_path_params(), tx_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        if (consensus != nullptr)
        {
          const auto tx_view = consensus->get_view(tx_id.version);
          const auto committed_seqno = consensus->get_committed_seqno();
          const auto committed_view = consensus->get_view(committed_seqno);

          GetTxStatus::Out out;
          out.status = ccf::get_tx_status(
            tx_id.term, tx_id.version, tx_view, committed_view, committed_seqno);
          return make_success(out);
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Consensus is not yet configured");
      };
      make_command_endpoint(
        "tx/{view}/{seqno}", HTTP_GET, json_command_adapter(get_tx_status))
        .set_auto_schema<void, GetTxStatus::Out>()
        .install();

      auto get_metrics = [this](auto& args, nlohmann::json&& params) {
        auto result = metrics.get_metrics();
        return make_success(result);
      };
      make_command_endpoint(
        "metrics", HTTP_GET, json_command_adapter(get_metrics))
        .set_auto_schema<void, GetMetrics::Out>()
        .set_execute_locally(true)
        .install();

      auto make_signature = [this](auto& args, nlohmann::json&& params) {
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
      make_command_endpoint(
        "mkSign", HTTP_POST, json_command_adapter(make_signature))
        .set_auto_schema<void, bool>()
        .install();

      if (certs != nullptr)
      {
        auto user_id = [this](auto& args, nlohmann::json&& params) {
          if (certs == nullptr)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              "This frontend does not support 'user_id'");
          }

          auto caller_id = args.caller_id;

          if (!params.is_null())
          {
            const GetUserId::In in = params;
            auto certs_view = args.tx.get_read_only_view(*certs);
            auto caller_id_opt = certs_view->get(in.cert);

            if (!caller_id_opt.has_value())
            {
              return make_error(
                HTTP_STATUS_BAD_REQUEST, "Certificate not recognised");
            }

            caller_id = caller_id_opt.value();
          }

          return make_success(GetUserId::Out{caller_id});
        };
        make_read_only_endpoint(
          "user_id", HTTP_GET, json_read_only_adapter(user_id))
          .set_auto_schema<GetUserId::In, GetUserId::Out>()
          .install();
      }

      auto get_primary_info = [this](auto& args, nlohmann::json&& params) {
        if ((nodes != nullptr) && (consensus != nullptr))
        {
          NodeId primary_id = consensus->primary();
          auto current_view = consensus->get_view();

          auto nodes_view = args.tx.get_read_only_view(*nodes);
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
      make_read_only_endpoint(
        "primary_info", HTTP_GET, json_read_only_adapter(get_primary_info))
        .set_auto_schema<void, GetPrimaryInfo::Out>()
        .install();

      auto get_network_info = [this](auto& args, nlohmann::json&& params) {
        GetNetworkInfo::Out out;
        if (consensus != nullptr)
        {
          out.primary_id = consensus->primary();
        }

        auto nodes_view = args.tx.get_read_only_view(*nodes);
        nodes_view->foreach([&out](const NodeId& nid, const NodeInfo& ni) {
          if (ni.status == ccf::NodeStatus::TRUSTED)
          {
            out.nodes.push_back({nid, ni.pubhost, ni.rpcport});
          }
          return true;
        });

        return make_success(out);
      };
      make_read_only_endpoint(
        "network_info", HTTP_GET, json_read_only_adapter(get_network_info))
        .set_auto_schema<void, GetNetworkInfo::Out>()
        .install();

      auto get_code = [this](auto& args, nlohmann::json&& params) {
        GetCode::Out out;

        auto code_view = args.tx.get_read_only_view(*node_code_ids);
        code_view->foreach(
          [&out](const ccf::CodeDigest& cd, const ccf::CodeStatus& cs) {
            auto digest = fmt::format("{:02x}", fmt::join(cd, ""));
            out.versions.push_back({digest, cs});
            return true;
          });

        return make_success(out);
      };
      make_read_only_endpoint(
        "code", HTTP_GET, json_read_only_adapter(get_code))
        .set_auto_schema<void, GetCode::Out>()
        .install();

      auto get_nodes_by_rpc_address = [this](
                                        auto& args, nlohmann::json&& params) {
        const auto in = params.get<GetNodesByRPCAddress::In>();

        GetNodesByRPCAddress::Out out;
        auto nodes_view = args.tx.get_read_only_view(*nodes);
        nodes_view->foreach([&in, &out](const NodeId& nid, const NodeInfo& ni) {
          if (ni.rpchost == in.host && ni.rpcport == in.port)
          {
            if (ni.status != ccf::NodeStatus::RETIRED || in.retired)
            {
              out.nodes.push_back({nid, ni.status});
            }
          }
          return true;
        });

        return make_success(out);
      };
      make_read_only_endpoint(
        "node/ids", HTTP_GET, json_read_only_adapter(get_nodes_by_rpc_address))
        .set_auto_schema<GetNodesByRPCAddress::In, GetNodesByRPCAddress::Out>()
        .install();

      auto list_methods_fn = [this](kv::Tx& tx, nlohmann::json&& params) {
        ListMethods::Out out;

        list_methods(tx, out);

        std::sort(out.methods.begin(), out.methods.end());

        return make_success(out);
      };
      make_endpoint("api", HTTP_GET, json_adapter(list_methods_fn))
        .set_auto_schema<void, ListMethods::Out>()
        .install();

      auto get_schema = [this](auto& args, nlohmann::json&& params) {
        const auto in = params.get<GetSchema::In>();

        auto j = nlohmann::json::object();

        const auto it = fully_qualified_endpoints.find(in.method);
        if (it != fully_qualified_endpoints.end())
        {
          for (const auto& [verb, endpoint] : it->second)
          {
            std::string verb_name = verb.c_str();
            std::transform(
              verb_name.begin(),
              verb_name.end(),
              verb_name.begin(),
              [](unsigned char c) { return std::tolower(c); });
            j[verb_name] =
              GetSchema::Out{endpoint.params_schema, endpoint.result_schema};
          }
        }

        const auto templated_it = templated_endpoints.find(in.method);
        if (templated_it != templated_endpoints.end())
        {
          for (const auto& [verb, endpoint] : templated_it->second)
          {
            std::string verb_name = verb.c_str();
            std::transform(
              verb_name.begin(),
              verb_name.end(),
              verb_name.begin(),
              [](unsigned char c) { return std::tolower(c); });
            j[verb_name] =
              GetSchema::Out{endpoint.params_schema, endpoint.result_schema};
          }
        }

        if (j.empty())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format("Method {} not recognised", in.method));
        }

        return make_success(j);
      };
      make_command_endpoint(
        "api/schema", HTTP_GET, json_command_adapter(get_schema))
        .set_auto_schema<GetSchema>()
        .install();

      auto get_receipt = [this](auto& args, nlohmann::json&& params) {
        kv::TxID tx_id;
        std::string error;
        if (!get_tx_id_from_path(
              args.rpc_ctx->get_request_path_params(), tx_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        if (history != nullptr)
        {
          const auto tx_view = consensus->get_view(tx_id.version);
          const auto committed_seqno = consensus->get_committed_seqno();
          const auto committed_view = consensus->get_view(committed_seqno);

          const auto status = ccf::get_tx_status(
            tx_id.term, tx_id.version, tx_view, committed_view, committed_seqno);

          if (status != ccf::TxStatus::Committed)
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              fmt::format(
                "Receipts are only available for committed transactions. "
                "Requested transaction {}.{} is {}",
                tx_id.term,
                tx_id.version,
                ccf::tx_status_to_str(status)));
          }

          try
          {
            auto p = history->get_receipt(tx_id.version);
            const GetReceipt::Out out{p};

            return make_success(out);
          }
          catch (const std::exception& e)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              fmt::format(
                "Unable to produce receipt for Tx ID {}.{} : {}",
                tx_id.term,
                tx_id.version,
                e.what()));
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR, "Unable to produce receipt");
      };
      make_command_endpoint(
        "receipt/{view}/{seqno}", HTTP_GET, json_command_adapter(get_receipt))
        .set_auto_schema<void, GetReceipt::Out>()
        .install();

      auto verify_receipt = [this](auto& args, nlohmann::json&& params) {
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
      make_command_endpoint(
        "receipt/verify", HTTP_POST, json_command_adapter(verify_receipt))
        .set_auto_schema<VerifyReceipt>()
        .install();
    }

    void tick(
      std::chrono::milliseconds elapsed,
      kv::Consensus::Statistics stats) override
    {
      metrics.track_tx_rates(elapsed, stats);

      EndpointRegistry::tick(elapsed, stats);
    }
  };
}
