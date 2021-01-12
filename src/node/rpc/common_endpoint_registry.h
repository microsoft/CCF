// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "endpoint_registry.h"
#include "http/http_consts.h"
#include "http/ws_consts.h"
#include "json_handler.h"
#include "node/code_id.h"
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
   * Extends the basic EndpointRegistry with methods which should be present
   * on all frontends
   */
  class CommonEndpointRegistry : public EndpointRegistry
  {
  protected:
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
    AbstractNodeState& node;

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

  public:
    CommonEndpointRegistry(
      const std::string& method_prefix_,
      kv::Store& store,
      AbstractNodeState& node_state,
      const std::string& certs_table_name = "") :
      EndpointRegistry(method_prefix_, store, certs_table_name),
      node(node_state)
    {}

    void init_handlers() override
    {
      EndpointRegistry::init_handlers();

      auto get_commit = [this](auto&, nlohmann::json&&) {
        const auto last_committed = get_last_committed_txid_v1();
        if (last_committed.has_value())
        {
          const auto [view, seqno] = last_committed.value();
          return make_success(GetCommit::Out{view, seqno});
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Failed to get commit info from Consensus.");
      };
      make_command_endpoint(
        "commit", HTTP_GET, json_command_adapter(get_commit), no_auth_required)
        .set_execute_locally(true)
        .set_auto_schema<void, GetCommit::Out>()
        .install();

      auto get_tx_status = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<GetTxStatus::In>();

        GetTxStatus::Out out;
        out.status = get_status_for_txid_v1(in.view, in.seqno);
        return make_success(out);
      };
      make_command_endpoint(
        "tx", HTTP_GET, json_command_adapter(get_tx_status), no_auth_required)
        .set_auto_schema<GetTxStatus>()
        .install();

      make_command_endpoint(
        "local_tx",
        HTTP_GET,
        json_command_adapter(get_tx_status),
        no_auth_required)
        .set_auto_schema<GetTxStatus>()
        .set_execute_locally(true)
        .install();

      auto user_id = [this](auto& args, nlohmann::json&& params) {
        GetUserId::Out out;

        if (!params.is_null())
        {
          const GetUserId::In in = params;
          auto certs_view =
            args.tx.template get_read_only_view<CertDERs>(certs_table_name);
          std::vector<uint8_t> pem(in.cert.begin(), in.cert.end());
          std::vector<uint8_t> der = tls::make_verifier(pem)->der_cert_data();
          auto caller_id_opt = certs_view->get(der);

          if (!caller_id_opt.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::UnknownCertificate,
              "Certificate not recognised.");
          }

          out.caller_id = caller_id_opt.value();
        }
        else if (
          auto user_cert_ident =
            args.template try_get_caller<ccf::UserCertAuthnIdentity>())
        {
          out.caller_id = user_cert_ident->user_id;
        }
        else if (
          auto member_cert_ident =
            args.template try_get_caller<ccf::MemberCertAuthnIdentity>())
        {
          out.caller_id = member_cert_ident->member_id;
        }
        else if (
          auto user_sig_ident =
            args.template try_get_caller<ccf::UserSignatureAuthnIdentity>())
        {
          out.caller_id = user_cert_ident->user_id;
        }
        else if (
          auto member_sig_ident =
            args.template try_get_caller<ccf::MemberSignatureAuthnIdentity>())
        {
          out.caller_id = member_cert_ident->member_id;
        }

        return make_success(out);
      };
      make_read_only_endpoint(
        "user_id",
        HTTP_GET,
        json_read_only_adapter(user_id),
        {user_cert_auth_policy,
         user_signature_auth_policy,
         member_cert_auth_policy,
         member_signature_auth_policy})
        .set_auto_schema<GetUserId::In, GetUserId::Out>()
        .install();

      auto get_primary_info = [this](auto& args, nlohmann::json&&) {
        if (consensus != nullptr)
        {
          NodeId primary_id = consensus->primary();
          auto current_view = consensus->get_view();

          auto nodes_view =
            args.tx.template get_read_only_view<Nodes>(Tables::NODES);
          auto info = nodes_view->get(primary_id);

          if (info)
          {
            GetPrimaryInfo::Out out;
            out.primary_id = primary_id;
            out.primary_host = info->pubhost;
            out.primary_port = info->pubport;
            out.current_view = current_view;
            return make_success(out);
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Primary unknown.");
      };
      make_read_only_endpoint(
        "primary_info",
        HTTP_GET,
        json_read_only_adapter(get_primary_info),
        no_auth_required)
        .set_auto_schema<void, GetPrimaryInfo::Out>()
        .install();

      auto get_network_info = [this](auto& args, nlohmann::json&&) {
        GetNetworkInfo::Out out;
        if (consensus != nullptr)
        {
          out.primary_id = consensus->primary();
        }

        auto nodes_view =
          args.tx.template get_read_only_view<Nodes>(Tables::NODES);
        nodes_view->foreach([&out](const NodeId& nid, const NodeInfo& ni) {
          if (ni.status == ccf::NodeStatus::TRUSTED)
          {
            out.nodes.push_back({nid, ni.pubhost, ni.pubport});
          }
          return true;
        });

        return make_success(out);
      };
      make_read_only_endpoint(
        "network_info",
        HTTP_GET,
        json_read_only_adapter(get_network_info),
        no_auth_required)
        .set_auto_schema<void, GetNetworkInfo::Out>()
        .install();

      auto get_code = [](auto& args, nlohmann::json&&) {
        GetCode::Out out;

        auto code_view =
          args.tx.template get_read_only_view<CodeIDs>(Tables::NODE_CODE_IDS);
        code_view->foreach(
          [&out](const ccf::CodeDigest& cd, const ccf::CodeStatus& cs) {
            auto digest = fmt::format("{:02x}", fmt::join(cd, ""));
            out.versions.push_back({digest, cs});
            return true;
          });

        return make_success(out);
      };
      make_read_only_endpoint(
        "code", HTTP_GET, json_read_only_adapter(get_code), no_auth_required)
        .set_auto_schema<void, GetCode::Out>()
        .install();

      auto get_nodes_by_rpc_address = [](auto& args, nlohmann::json&& params) {
        const auto in = params.get<GetNodesByRPCAddress::In>();

        GetNodesByRPCAddress::Out out;
        auto nodes_view =
          args.tx.template get_read_only_view<Nodes>(Tables::NODES);
        nodes_view->foreach([&in, &out](const NodeId& nid, const NodeInfo& ni) {
          if (ni.pubhost == in.host && ni.pubport == in.port)
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
        "node/ids",
        HTTP_GET,
        json_read_only_adapter(get_nodes_by_rpc_address),
        no_auth_required)
        .set_auto_schema<GetNodesByRPCAddress::In, GetNodesByRPCAddress::Out>()
        .install();

      auto openapi = [this](kv::Tx& tx, nlohmann::json&&) {
        auto document = generate_openapi_document_v1(
          tx,
          openapi_info.title,
          openapi_info.description,
          openapi_info.document_version);
        return make_success(document);
      };
      make_endpoint("api", HTTP_GET, json_adapter(openapi), no_auth_required)
        .set_auto_schema<void, GetAPI::Out>()
        .install();

      auto endpoint_metrics_fn = [this](kv::Tx& tx, nlohmann::json&&) {
        EndpointMetrics::Out out;
        endpoint_metrics(tx, out);

        return make_success(out);
      };
      make_endpoint(
        "endpoint_metrics",
        HTTP_GET,
        json_adapter(endpoint_metrics_fn),
        no_auth_required)
        .set_auto_schema<void, EndpointMetrics::Out>()
        .install();

      auto get_receipt = [this](auto&, nlohmann::json&& params) {
        const auto in = params.get<GetReceipt::In>();

        std::string error_reason;
        const auto opt_r = get_receipt_for_index_v1(in.commit, error_reason);
        if (opt_r.has_value())
        {
          GetReceipt::Out out;
          out.receipt = opt_r.value();
          return make_success(out);
        }
        else
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            std::move(error_reason));
        }
      };
      make_command_endpoint(
        "receipt",
        HTTP_GET,
        json_command_adapter(get_receipt),
        no_auth_required)
        .set_auto_schema<GetReceipt>()
        .install();

      auto verify_receipt = [this](auto&, nlohmann::json&& params) {
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
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              fmt::format("Unable to verify receipt: {}", e.what()));
          }
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Unable to verify receipt.");
      };
      make_command_endpoint(
        "receipt/verify",
        HTTP_POST,
        json_command_adapter(verify_receipt),
        no_auth_required)
        .set_auto_schema<VerifyReceipt>()
        .install();
    }
  };
}
