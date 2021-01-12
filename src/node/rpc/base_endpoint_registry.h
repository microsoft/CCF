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
          // TODO: Why don't we include this in BFT?
          if (consensus != nullptr && consensus->type() != ConsensusType::BFT)
          {
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

    ccf::TxStatus get_status_for_txid_v1(
      kv::Consensus::View view, kv::Consensus::SeqNo seqno)
    {
      if (consensus != nullptr)
      {
        const auto tx_view = consensus->get_view(seqno);
        const auto committed_seqno = consensus->get_committed_seqno();
        const auto committed_view = consensus->get_view(committed_seqno);

        return ccf::evaluate_tx_status(
          view, seqno, tx_view, committed_view, committed_seqno);
      }

      return ccf::TxStatus::Unknown;
    }

    std::optional<std::pair<kv::Consensus::View, kv::Consensus::SeqNo>>
    get_last_committed_txid_v1()
    {
      if (consensus != nullptr)
      {
        return consensus->get_committed_txid();
      }

      return std::nullopt;
    }

    nlohmann::json generate_openapi_document_v1(
      kv::ReadOnlyTx& tx,
      const std::string& title,
      const std::string& description,
      const std::string& document_version)
    {
      auto document =
        ds::openapi::create_document(title, description, document_version);
      build_api(document, tx);
      return document;
    }

    std::optional<std::vector<uint8_t>> get_receipt_for_index_v1(
      kv::Consensus::SeqNo seqno, std::string& error_reason)
    {
      try
      {
        if (history != nullptr)
        {
          try
          {
            return history->get_receipt(seqno);
          }
          catch (const std::exception& e)
          {
            error_reason = e.what();
            return std::nullopt;
          }
        }

        error_reason = "Node is not yet initialised";
        return std::nullopt;
      }
      catch (const std::exception& e)
      {
        error_reason = "Exception thrown during execution";
        return std::nullopt;
      }
    }

    Quote get_quote_for_this_node_v1(kv::ReadOnlyTx& tx)
    {
      const auto node_id = node.get_node_id();

      return get_quote_for_node(tx, node_id);
    }
  };
}
