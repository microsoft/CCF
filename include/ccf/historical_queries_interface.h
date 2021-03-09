// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/receipt.h"
#include "consensus/ledger_enclave_types.h"
#include "kv/store.h"
#include "node/history.h"
#include "tls/base64.h"

#include <chrono>
#include <memory>

namespace ccf::historical
{
  struct TxReceipt
  {
    std::vector<uint8_t> signature = {};
    HistoryTree::Hash root = {};
    std::shared_ptr<ccf::HistoryTree::Path> path = {};
    ccf::NodeId node_id = {};

    TxReceipt(
      const std::vector<uint8_t>& s_,
      const HistoryTree::Hash& r_,
      std::shared_ptr<ccf::HistoryTree::Path> p_,
      const NodeId& n_) :
      signature(s_),
      root(r_),
      path(p_),
      node_id(n_)
    {}

    void describe_receipt(ccf::Receipt& r)
    {
      r.signature = tls::b64_from_raw(signature);
      r.root = root.to_string();
      for (const auto& node : *path)
      {
        ccf::Receipt::Element n;
        if (node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT)
        {
          n.left = node.hash.to_string();
        }
        else
        {
          n.right = node.hash.to_string();
        }
        r.proof.emplace_back(std::move(n));
      }
      r.leaf = path->leaf().to_string();
      r.node_id = node_id;
    }
  };

  using TxReceiptPtr = std::shared_ptr<TxReceipt>;
  using StorePtr = std::shared_ptr<kv::Store>;

  struct State
  {
    /// Read-only historical store at transaction_id
    StorePtr store = nullptr;
    /// Receipt for ledger entry at transaction_id
    TxReceiptPtr receipt = nullptr;
    /// View and Sequence Number for the State
    kv::TxID transaction_id;

    State(
      const StorePtr& store_,
      const TxReceiptPtr& receipt_,
      const kv::TxID& transaction_id_) :
      store(store_),
      receipt(receipt_),
      transaction_id(transaction_id_)
    {}
  };

  using StatePtr = std::shared_ptr<State>;

  /** This is a caller-defined key for each historical query request. For
   * instance, you may wish to use callerID or sessionID to allow a single
   * active request per caller or session, or maintain an LRU to cap the total
   * number of active requests.
   */
  using RequestHandle = size_t;

  using ExpiryDuration = std::chrono::seconds;

  /** Stores the progress of historical query requests.
   *
   * A request will generally need to be made multiple times (with the same
   * handle and range) before the response is available, as the historical state
   * is asynchronously retrieved from the ledger and then validated. If the same
   * handle is used for a new range, the state for the old range will be
   * discarded. State is also discarded after the handle's expiry duration, or
   * when drop_request is called for a given handle. The management of requests
   * (how many unique handles are concurrently active, how they are correlated
   * across HTTP requests, how the active quota is divided between callers) is
   * left to the calling system.
   */
  class AbstractStateCache
  {
  public:
    virtual ~AbstractStateCache() = default;

    /** Set the default time after which a request's state will be deleted, and
     * will not be accessible without retrieving it again from the ledger. Any
     * call to get_store_XXX which doesn't pass an explicit seconds_until_expiry
     * will reset the timer to this default duration.
     */
    virtual void set_default_expiry_duration(
      ExpiryDuration seconds_until_expiry) = 0;

    /** Retrieve a Store containing the state written at the given seqno.
     *
     * See @c get_store_range for a description of the caching behaviour. This
     * is equivalent to get_store_at(handle, seqno, seqno), but returns nullptr
     * if the state is currently unavailable.
     */
    virtual StorePtr get_store_at(
      RequestHandle handle,
      kv::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) = 0;

    /** Same as @c get_store_at but uses default expiry value.
     * @see get_store_at
     */
    virtual StorePtr get_store_at(RequestHandle handle, kv::SeqNo seqno) = 0;

    /** Retrieve a full state at a given seqno, including the Store, the TxID
     * assigned by consensus, and an offline-verifiable receipt for the Tx.
     */
    virtual StatePtr get_state_at(RequestHandle handle, kv::SeqNo seqno) = 0;

    /** Retrieve a range of Stores containing the state written at the given
     * indices.
     *
     * If this is not currently available, this function returns an empty vector
     * and begins fetching the ledger entry asynchronously. This will generally
     * be true for the first call for a given seqno, and it may take some time
     * to completely fetch and validate. The call should be repeated later with
     * the same arguments to retrieve the requested entries. This state is kept
     * until it is deleted for one of the following reasons:
     *  - A call to @c drop_request
     *  - @c seconds_until_expiry seconds elapse without calling this function
     *  - This handle is used to request a different seqno or range
     *
     * The range is inclusive of both start_seqno and end_seqno. If a non-empty
     * vector is returned, it will always contain the full requested range; the
     * vector will be of length (end_seqno - start_seqno + 1) and will contain
     * no nullptrs.
     */
    virtual std::vector<StorePtr> get_store_range(
      RequestHandle handle,
      kv::SeqNo start_seqno,
      kv::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) = 0;

    /** Same as @c get_store_range but uses default expiry value.
     * @see get_store_range
     */
    virtual std::vector<StorePtr> get_store_range(
      RequestHandle handle, kv::SeqNo start_seqno, kv::SeqNo end_seqno) = 0;

    /** Drop state for the given handle.
     *
     * May be used to free up space once a historical query has been resolved,
     * more aggressively than waiting for the requests to expire.
     */
    virtual bool drop_request(RequestHandle handle) = 0;
  };
}