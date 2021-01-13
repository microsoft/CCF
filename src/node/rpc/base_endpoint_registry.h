// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "endpoint_registry.h"
#include "node/quote.h"
#include "node/rpc/node_interface.h"

namespace ccf
{
  enum class QuoteFormat
  {
    oe_sgx_v1,
  };

  DECLARE_JSON_ENUM(
    QuoteFormat,
    {{QuoteFormat::oe_sgx_v1, "OE_SGX_v1"}})

  /*
   * Extends the basic EndpointRegistry with helper API methods for retrieving
   * core CCF properties.
   */
  class BaseEndpointRegistry : public EndpointRegistry
  {
  protected:
    AbstractNodeState& node;

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
        else
        {
          tx_status = ccf::TxStatus::Unknown;
        }

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
      kv::Consensus::SeqNo seqno, std::vector<uint8_t>& receipt)
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

    std::string get_quote_for_this_node_v1(
      kv::ReadOnlyTx& tx, QuoteFormat& format, std::vector<uint8_t>& raw_quote)
    {
      const auto node_id = node.get_node_id();
      auto nodes_view = tx.get_read_only_view<ccf::Nodes>(Tables::NODES);
      const auto node_info = nodes_view->get(node_id);

      if (!node_info.has_value())
      {
        return fmt::format("{} is not a known node", node_id);
      }

      format = QuoteFormat::oe_sgx_v1;
      raw_quote = node_info->quote;
      return "";
    }
  };
}
