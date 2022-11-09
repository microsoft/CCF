// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/read_only_store.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/receipt.h"
#include "ccf/seq_no_collection.h"
#include "ccf/tx_id.h"

#include <chrono>
#include <memory>

namespace ccf::historical
{
  struct State
  {
    /// Read-only historical store at transaction_id
    kv::ReadOnlyStorePtr store = nullptr;
    /// Receipt for ledger entry at transaction_id
    TxReceiptImplPtr receipt = nullptr;
    /// View and Sequence Number for the State
    ccf::TxID transaction_id;

    State(
      const kv::ReadOnlyStorePtr& store_,
      const TxReceiptImplPtr& receipt_,
      const ccf::TxID& transaction_id_) :
      store(store_),
      receipt(receipt_),
      transaction_id(transaction_id_)
    {}

    bool operator==(const State& other) const
    {
      return store == other.store && receipt == other.receipt &&
        transaction_id == other.transaction_id;
    };
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
   * when drop_cached_states is called for a given handle. The management of
   * requests (how many unique handles are concurrently active, how they are
   * correlated across HTTP requests, how the active quota is divided between
   * callers) is left to the calling system.
   */
  class AbstractStateCache : public ccf::AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractStateCache() = default;

    static char const* get_subsystem_name()
    {
      return "StateCache";
    }

    /** Set the default time after which a request's state will be deleted, and
     * will not be accessible without retrieving it again from the ledger. Any
     * call to get_store_XXX which doesn't pass an explicit seconds_until_expiry
     * will reset the timer to this default duration.
     */
    virtual void set_default_expiry_duration(
      ExpiryDuration seconds_until_expiry) = 0;

    /** EXPERIMENTAL: Set the tracking of deletes on missing keys for historical
     * queries.
     *
     * This is experimental but setting this to true ensures that the `tx_diff`
     * available in index handlers can observe deleted values.
     */
    virtual void track_deletes_on_missing_keys(bool track) = 0;

    /** Retrieve a Store containing the state written at the given seqno.
     *
     * See @c get_store_range for a description of the caching behaviour. This
     * is equivalent to get_store_at(handle, seqno, seqno), but returns nullptr
     * if the state is currently unavailable.
     */
    virtual kv::ReadOnlyStorePtr get_store_at(
      RequestHandle handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) = 0;

    /** Same as @c get_store_at but uses default expiry value.
     * @see get_store_at
     */
    virtual kv::ReadOnlyStorePtr get_store_at(
      RequestHandle handle, ccf::SeqNo seqno) = 0;

    /** Retrieve a full state at a given seqno, including the Store, the TxID
     * assigned by consensus, and an offline-verifiable receipt for the Tx.
     */
    virtual StatePtr get_state_at(
      RequestHandle handle,
      ccf::SeqNo seqno,
      ExpiryDuration seconds_until_expiry) = 0;

    /** Same as @c get_state_at but uses default expiry value.
     * @see get_state_at
     */
    virtual StatePtr get_state_at(RequestHandle handle, ccf::SeqNo seqno) = 0;

    /** Retrieve a range of Stores containing the state written at the given
     * indices.
     *
     * If this is not currently available, this function returns an empty vector
     * and begins fetching the ledger entry asynchronously. This will generally
     * be true for the first call for a given seqno, and it may take some time
     * to completely fetch and validate. The call should be repeated later with
     * the same arguments to retrieve the requested entries. This state is kept
     * until it is deleted for one of the following reasons:
     *  - A call to @c drop_cached_states
     *  - @c seconds_until_expiry seconds elapse without calling this function
     *  - This handle is used to request a different seqno or range
     *
     * The range is inclusive of both start_seqno and end_seqno. If a non-empty
     * vector is returned, it will always contain the full requested range; the
     * vector will be of length (end_seqno - start_seqno + 1) and will contain
     * no nullptrs.
     */
    virtual std::vector<kv::ReadOnlyStorePtr> get_store_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) = 0;

    /** Same as @c get_store_range but uses default expiry value.
     * @see get_store_range
     */
    virtual std::vector<kv::ReadOnlyStorePtr> get_store_range(
      RequestHandle handle, ccf::SeqNo start_seqno, ccf::SeqNo end_seqno) = 0;

    /** Retrieve a range of states at the given indices, including the Store,
     * the TxID assigned by consensus, and an offline-verifiable receipt for
     * the Tx.
     */
    virtual std::vector<StatePtr> get_state_range(
      RequestHandle handle,
      ccf::SeqNo start_seqno,
      ccf::SeqNo end_seqno,
      ExpiryDuration seconds_until_expiry) = 0;

    /** Same as @c get_state_range but uses default expiry value.
     * @see get_state_range
     */
    virtual std::vector<StatePtr> get_state_range(
      RequestHandle handle, ccf::SeqNo start_seqno, ccf::SeqNo end_seqno) = 0;

    /** Retrieve stores for a set of given indices.
     */
    virtual std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      RequestHandle handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry) = 0;
    virtual std::vector<kv::ReadOnlyStorePtr> get_stores_for(
      RequestHandle handle, const SeqNoCollection& seqnos) = 0;

    /** Retrieve states for a set of given indices.
     */
    virtual std::vector<StatePtr> get_states_for(
      RequestHandle handle,
      const SeqNoCollection& seqnos,
      ExpiryDuration seconds_until_expiry) = 0;
    virtual std::vector<StatePtr> get_states_for(
      RequestHandle handle, const SeqNoCollection& seqnos) = 0;

    /** Drop state for the given handle.
     *
     * May be used to free up space once a historical query has been resolved,
     * more aggressively than waiting for the states to expire.
     */
    virtual bool drop_cached_states(RequestHandle handle) = 0;
  };
}