// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/base_endpoint_registry.h"

#include "ccf/pal/locking.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/users.h"
#include "enclave/enclave_time.h"
#include "kv/kv_types.h"

namespace ccf
{
  BaseEndpointRegistry::BaseEndpointRegistry(
    const std::string& method_prefix_, ccfapp::AbstractNodeContext& context_) :
    ccf::endpoints::EndpointRegistry(method_prefix_),
    context(context_)
  {}

  ApiResult BaseEndpointRegistry::get_view_history_v1(
    std::vector<ccf::TxID>& history, ccf::View since)
  {
    try
    {
      if (consensus != nullptr)
      {
        if (since < 1)
        {
          // views start at 2 so 1 is the start of time
          return ApiResult::InvalidArgs;
        }
        const auto view_history = consensus->get_view_history_since(since);
        for (ccf::View i = 0; i < view_history.size(); i++)
        {
          const auto view = i + since;
          const auto first_seqno = view_history[i];
          history.push_back({view, first_seqno});
        }
      }

      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_status_for_txid_v1(
    ccf::View view, ccf::SeqNo seqno, ccf::TxStatus& tx_status)
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

      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_last_committed_txid_v1(
    ccf::View& view, ccf::SeqNo& seqno)
  {
    if (consensus != nullptr)
    {
      try
      {
        const auto [v, s] = consensus->get_committed_txid();
        view = v;
        seqno = s;
        return ApiResult::OK;
      }
      catch (const std::exception& e)
      {
        LOG_TRACE_FMT("{}", e.what());
        return ApiResult::InternalError;
      }
    }
    else
    {
      return ApiResult::Uninitialised;
    }
  }

  ApiResult BaseEndpointRegistry::generate_openapi_document_v1(
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
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_quote_for_this_node_v1(
    kv::ReadOnlyTx& tx, QuoteInfo& quote_info)
  {
    try
    {
      const auto node_id = context.get_node_id();
      auto nodes = tx.ro<ccf::Nodes>(Tables::NODES);
      const auto node_info = nodes->get(node_id);

      if (!node_info.has_value())
      {
        LOG_TRACE_FMT("{} is not a known node", node_id);
        return ApiResult::NotFound;
      }

      quote_info = node_info->quote_info;
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_id_for_this_node_v1(NodeId& node_id)
  {
    try
    {
      node_id = context.get_node_id();
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_quotes_for_all_trusted_nodes_v1(
    kv::ReadOnlyTx& tx, std::map<NodeId, QuoteInfo>& quotes)
  {
    try
    {
      std::map<NodeId, QuoteInfo> tmp;
      auto nodes = tx.ro<ccf::Nodes>(Tables::NODES);
      nodes->foreach([&tmp](const NodeId& node_id, const NodeInfo& ni) {
        if (ni.status == ccf::NodeStatus::TRUSTED)
        {
          tmp[node_id] = ni.quote_info;
        }
        return true;
      });

      quotes = std::move(tmp);
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_view_for_seqno_v1(
    ccf::SeqNo seqno, ccf::View& view)
  {
    try
    {
      if (consensus != nullptr)
      {
        const auto v = consensus->get_view(seqno);
        if (v != ccf::VIEW_UNKNOWN)
        {
          view = v;
          return ApiResult::OK;
        }
        else
        {
          return ApiResult::NotFound;
        }
      }
      else
      {
        return ApiResult::Uninitialised;
      }
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_user_data_v1(
    kv::ReadOnlyTx& tx, const UserId& user_id, nlohmann::json& user_data)
  {
    try
    {
      auto users_data = tx.ro<ccf::UserInfo>(Tables::USER_INFO);
      auto ui = users_data->get(user_id);
      if (!ui.has_value())
      {
        return ApiResult::NotFound;
      }

      user_data = ui->user_data;
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_member_data_v1(
    kv::ReadOnlyTx& tx, const MemberId& member_id, nlohmann::json& member_data)
  {
    try
    {
      auto member_info = tx.ro<ccf::MemberInfo>(Tables::MEMBER_INFO);
      auto mi = member_info->get(member_id);
      if (!mi.has_value())
      {
        return ApiResult::NotFound;
      }

      member_data = mi->member_data;
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_user_cert_v1(
    kv::ReadOnlyTx& tx, const UserId& user_id, crypto::Pem& user_cert_pem)
  {
    try
    {
      auto user_certs = tx.ro<ccf::UserCerts>(Tables::USER_CERTS);
      auto uc = user_certs->get(user_id);
      if (!uc.has_value())
      {
        return ApiResult::NotFound;
      }

      user_cert_pem = uc.value();
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_member_cert_v1(
    kv::ReadOnlyTx& tx, const MemberId& member_id, crypto::Pem& member_cert_pem)
  {
    try
    {
      auto member_certs = tx.ro<ccf::MemberCerts>(Tables::MEMBER_CERTS);
      auto mc = member_certs->get(member_id);
      if (!mc.has_value())
      {
        return ApiResult::NotFound;
      }

      member_cert_pem = mc.value();
      return ApiResult::OK;
    }
    catch (const std::exception& e)
    {
      LOG_TRACE_FMT("{}", e.what());
      return ApiResult::InternalError;
    }
  }

  ApiResult BaseEndpointRegistry::get_untrusted_host_time_v1(::timespec& time)
  {
    const std::chrono::microseconds now_us = ccf::get_enclave_time();

    constexpr auto us_per_s = 1'000'000;
    time.tv_sec = now_us.count() / us_per_s;
    time.tv_nsec = (now_us.count() % us_per_s) * 1'000;

    return ApiResult::OK;
  }

  ApiResult BaseEndpointRegistry::get_metrics_v1(
    EndpointMetrics& endpoint_metrics)
  {
    endpoint_metrics.metrics.clear();
    std::lock_guard<ccf::pal::Mutex> guard(metrics_lock);
    for (const auto& [path, verb_metrics] : metrics)
    {
      for (const auto& [verb, metric] : verb_metrics)
      {
        endpoint_metrics.metrics.push_back(
          {path,
           verb,
           metric.calls,
           metric.errors,
           metric.failures,
           metric.retries});
      }
    }
    return ApiResult::OK;
  }
}
