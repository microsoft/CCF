// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "endpoint_registry.h"
#include "node/quote.h"
#include "node/rpc/node_interface.h"

namespace ccf
{
  struct Quote
  {
    NodeId node_id = {};
    std::string raw = {}; // < Hex-encoded

    std::string error = {};
    std::string mrenclave = {}; // < Hex-encoded
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Quote)
  DECLARE_JSON_REQUIRED_FIELDS(Quote, node_id, raw)
  DECLARE_JSON_OPTIONAL_FIELDS(Quote, error, mrenclave)

  /*
   * Extends the basic EndpointRegistry with helper API methods for retrieving
   * core CCF properties.
   */
  class BaseEndpointRegistry : public EndpointRegistry
  {
  protected:
    AbstractNodeState& node;

    Quote get_quote_for_node(kv::ReadOnlyTx& tx, NodeId node_id)
    {
      auto nodes_view = tx.get_read_only_view<ccf::Nodes>(Tables::NODES);
      const auto node_info = nodes_view->get(node_id);
      if (node_info.has_value())
      {
        Quote q;
        q.node_id = node_id;

        if (node_info->status == ccf::NodeStatus::TRUSTED)
        {
          q.raw = fmt::format("{:02x}", fmt::join(node_info->quote, ""));

#ifdef GET_QUOTE
          auto code_id_opt = QuoteGenerator::get_code_id(node_info->quote);
          if (!code_id_opt.has_value())
          {
            q.error = fmt::format("Failed to retrieve code ID from quote");
          }
          else
          {
            q.mrenclave =
              fmt::format("{:02x}", fmt::join(code_id_opt.value(), ""));
          }
#endif
        }
        else
        {
          q.error = fmt::format(
            "Node {} status is not TRUSTED, currently {}",
            node_id,
            node_info->status);
        }

        return q;
      }
      else
      {
        throw std::runtime_error(
          fmt::format("{} is not a known node ID", node_id));
      }
    }

  public:
    BaseEndpointRegistry(
      const std::string& method_prefix_,
      kv::Store& store,
      AbstractNodeState& node_state,
      const std::string& certs_table_name = "") :
      EndpointRegistry(method_prefix_, store, certs_table_name),
      node(node_state)
    {}

    std::string get_status_for_txid_v1(
      kv::Consensus::View view,
      kv::Consensus::SeqNo seqno,
      ccf::TxStatus& tx_status)
    {
      try
      {
        if (consensus != nullptr)
        {
          const auto tx_view = consensus->get_view(seqno);
          const auto committed_seqno = consensus->get_committed_seqno();
          const auto committed_view = consensus->get_view(committed_seqno);

          tx_status = ccf::evaluate_tx_status(
            view, seqno, tx_view, committed_view, committed_seqno);
        }

        tx_status = ccf::TxStatus::Unknown;
        return "";
      }
      catch (const std::exception& e)
      {
        return fmt::format("Error finding tx status: {}", e.what());
      }
    }

    std::string get_last_committed_txid_v1(
      kv::Consensus::View& view, kv::Consensus::SeqNo& seqno)
    {
      if (consensus != nullptr)
      {
        try
        {
          const auto [v, s] = consensus->get_committed_txid();
          view = v;
          seqno = s;
          return "";
        }
        catch (const std::exception& e)
        {
          return fmt::format("Error retrieving commit: {}", e.what());
        }
      }

      return "Node is not initialised";
    }

    std::string generate_openapi_document_v1(
      kv::ReadOnlyTx& tx,
      const std::string& title,
      const std::string& description,
      const std::string& document_version,
      nlohmann::json& document)
    {
      try
      {
        document =
          ds::openapi::create_document(title, description, document_version);
        build_api(document, tx);
      }
      catch (const std::exception& e)
      {
        return fmt::format("Error generating OpenAPI document: {}", e.what());
      }

      return "";
    }

    std::string get_receipt_for_index_v1(
      kv::Consensus::SeqNo seqno,
      std::vector<uint8_t>& receipt)
    {
      if (history != nullptr)
      {
        try
        {
          receipt = history->get_receipt(seqno);
          return "";
        }
        catch (const std::exception& e)
        {
          return fmt::format(
            "Exception thrown while retrieving receipt: {}", e.what());
        }
      }

      return "Node is not yet initialised";
    }

    Quote get_quote_for_this_node_v1(kv::ReadOnlyTx& tx)
    {
      const auto node_id = node.get_node_id();

      return get_quote_for_node(tx, node_id);
    }
  };
}
