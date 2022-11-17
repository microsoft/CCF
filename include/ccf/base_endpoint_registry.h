// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/quote_info.h"
#include "ccf/endpoint_metrics.h"
#include "ccf/endpoint_registry.h"
#include "ccf/node_context.h"
#include "ccf/tx_status.h"

namespace ccf
{
  /** Lists the possible return codes from the versioned APIs in @c
   * ccf::BaseEndpointRegistry
   */
  enum class ApiResult
  {
    /** Call was successful, results can be used */
    OK = 0,
    /** The node is not yet initialised, and doesn't have access to the service
       needed to answer this call. Should only be returned if the API is called
       too early, during node construction. */
    Uninitialised,
    /** One of the arguments passed to the function is invalid. It may be
       outside the range of known values, or not be in the expected format. */
    InvalidArgs,
    /** The requsted value was not found. */
    NotFound,
    /** General error not covered by the cases above. Generally means that an
       unexpected exception was thrown during execution. */
    InternalError,
  };

  constexpr char const* api_result_to_str(ApiResult result)
  {
    switch (result)
    {
      case ApiResult::OK:
      {
        return "OK";
      }
      case ApiResult::Uninitialised:
      {
        return "Uninitialised";
      }
      case ApiResult::InvalidArgs:
      {
        return "InvalidArgs";
      }
      case ApiResult::NotFound:
      {
        return "NotFound";
      }
      case ApiResult::InternalError:
      {
        return "InternalError";
      }
      default:
      {
        return "Unhandled ApiResult";
      }
    }
  }

  /** Extends the basic @ref ccf::endpoints::EndpointRegistry with helper API
   * methods for retrieving core CCF properties.
   *
   * The API methods are versioned with a @c _vN suffix. App developers should
   * use the latest version which provides the values they need. Note that the
   * @c N in these versions is specific to each method name, and is not related
   * to a specific CCF release version. These APIs will be stable and supported
   * for several CCF releases.
   *
   * The methods have a consistent calling pattern, taking their arguments first
   * and setting results to the later out-parameters, passed by reference. All
   * return an @ref ApiResult, with value OK if the call succeeded.
   */
  class BaseEndpointRegistry : public ccf::endpoints::EndpointRegistry
  {
  protected:
    ccfapp::AbstractNodeContext& context;

  public:
    BaseEndpointRegistry(
      const std::string& method_prefix_, ccfapp::AbstractNodeContext& context_);

    ApiResult get_view_history_v1(std::vector<std::pair<ccf::View, ccf::SeqNo>>& history);

    /** Get the status of a transaction by ID, provided as a view+seqno pair.
     *
     * Note that this value is the node's local understanding of the status
     * of that transaction in the network at call time. For a given TxID, the
     * initial status is always UNKNOWN, and eventually becomes COMMITTED or
     * INVALID. See the documentation section titled "Verifying Transactions"
     * for more detail.
     *
     *         UNKNOWN [Initial status]
     *          v  ^
     *        PENDING
     *        v     v
     *  COMMITTED INVALID [Final statuses]
     *
     * This status is not sampled atomically per handler: if this is called
     * multiple times in a transaction handler, later calls may see more up to
     * date values than earlier calls. Once a final state (COMMITTED or INVALID)
     * has been reached, no further changes are possible.
     *
     * @see ccf::TxStatus
     */
    ApiResult get_status_for_txid_v1(
      ccf::View view, ccf::SeqNo seqno, ccf::TxStatus& tx_status);

    /** Get the ID of latest transaction known to be committed.
     */
    ApiResult get_last_committed_txid_v1(ccf::View& view, ccf::SeqNo& seqno);

    /** Generate an OpenAPI document describing the currently installed
     * endpoints.
     *
     * The document is compatible with OpenAPI version 3.0.0 - the _v1 suffix
     * describes the version of this API, not the returned document format.
     * Similarly, the document_version argument should be used to version the
     * returned document itself as the set of endpoints or their APIs change, it
     * does not affect the OpenAPI version of the format of the document.
     */
    ApiResult generate_openapi_document_v1(
      kv::ReadOnlyTx& tx,
      const std::string& title,
      const std::string& description,
      const std::string& document_version,
      nlohmann::json& document);

    /** Get a quote attesting to the hardware this node is running on.
     */
    ApiResult get_quote_for_this_node_v1(
      kv::ReadOnlyTx& tx, QuoteInfo& quote_info);

    /** Get the id of the currently executing node.
     */
    ApiResult get_id_for_this_node_v1(NodeId& node_id);

    /** Get quotes attesting to the hardware that each node in the service is
     * running on.
     */
    ApiResult get_quotes_for_all_trusted_nodes_v1(
      kv::ReadOnlyTx& tx, std::map<NodeId, QuoteInfo>& quotes);

    /** Get the view associated with a given seqno, to construct a valid TxID.
     */
    ApiResult get_view_for_seqno_v1(ccf::SeqNo seqno, ccf::View& view);

    /** Get the user data associated with a given user id.
     */
    ApiResult get_user_data_v1(
      kv::ReadOnlyTx& tx, const UserId& user_id, nlohmann::json& user_data);

    /** Get the member data associated with a given member id.
     */
    ApiResult get_member_data_v1(
      kv::ReadOnlyTx& tx,
      const MemberId& member_id,
      nlohmann::json& member_data);

    /** Get the certificate (PEM) of a given user id.
     */
    ApiResult get_user_cert_v1(
      kv::ReadOnlyTx& tx, const UserId& user_id, crypto::Pem& user_cert_pem);

    /** Get the certificate (PEM) of a given member id.
     */
    ApiResult get_member_cert_v1(
      kv::ReadOnlyTx& tx,
      const MemberId& member_id,
      crypto::Pem& member_cert_pem);

    /** Get untrusted time from the host of the currently executing node.
     */
    ApiResult get_untrusted_host_time_v1(::timespec& time);

    /** Get usage metrics from endpoints under the registry, including
     * number of calls, errors, failures and retries.
     */
    ApiResult get_metrics_v1(EndpointMetrics& endpoint_metrics);
  };
}
