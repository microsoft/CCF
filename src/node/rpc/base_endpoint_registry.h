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

  DECLARE_JSON_ENUM(QuoteFormat, {{QuoteFormat::oe_sgx_v1, "OE_SGX_v1"}})

  /** Extends the basic EndpointRegistry with helper API methods for retrieving
   * core CCF properties.
   *
   * The API methods are versioned with a @c _vN suffix. App developers should
   * use the latest version which provides the values they need. Note that the
   * @c N in these versions is specific to each method name, and is not related
   * to a specific CCF release version. These APIs will be stable and supported
   * for several CCF releases.
   *
   * The methods have a consistent calling pattern, taking their arguments first
   * and setting results to the later out-parameters, passed by reference. All
   * return an error string, describing the error if they fail. If this string
   * is empty, the call succeeded and the result(s) can be used.
   */
  class BaseEndpointRegistry : public EndpointRegistry
  {
  protected:
    AbstractNodeState& node;

  public:
    BaseEndpointRegistry(
      const std::string& method_prefix_,
      AbstractNodeState& node_state) :
      EndpointRegistry(method_prefix_),
      node(node_state)
    {}

    /** Get the status of a transaction by ID, provided as a view+seqno pair.
     * This is a node-local property - while it will converge on all nodes in
     * a healthy network, it is derived from distributed state rather than
     * distributed itself.
     * @see ccf::TxStatus
     */
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

    /** Get the ID of latest transaction known to be committed.
     */
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

    /** Generate an OpenAPI document describing the currently installed
     * endpoints.
     *
     * The document is compatible with OpenAPI version 3.0.0 - the _v1 suffix
     * describes the version of this API, not the returned document format.
     * Similarly, the document_version argument should be used to version the
     * returned document itself as the set of endpoints or their APIs change, it
     * does not affect the OpenAPI version of the format of the document.
     */
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

    /** Get a receipt for the transaction at the specified sequence number
     * containing a merkle tree path which proves that the service's ledger
     * contains the given transaction.
     */
    std::string get_receipt_for_seqno_v1(
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

    /** Get a quote attesting to the hardware this node is running on. The
     * format indicates how the raw_quote should be interpreted and verified.
     */
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
