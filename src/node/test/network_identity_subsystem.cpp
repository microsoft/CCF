// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/rpc/network_identity_subsystem.h"

#include "cose/cose_rs_ffi.h"
#include "crypto/openssl/ec_key_pair.h"
#include "node/rpc/network_identity_accessors.h"
#include "node/rpc/network_identity_chain_helpers.h"
#include "tasks/basic_task.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <deque>
#include <doctest/doctest.h>
#include <thread>

using namespace std::chrono_literals;

namespace
{
  // Build a synthetic CoseEndorsement covering range [begin_view:begin_seqno,
  // end_view:end_seqno]. Signature/key payloads are left empty: only the
  // range fields are exercised by the pure-helper validators tested here.
  ccf::CoseEndorsement make_range_endorsement(
    ccf::View begin_view,
    ccf::SeqNo begin_seqno,
    ccf::View end_view,
    ccf::SeqNo end_seqno,
    std::optional<ccf::kv::Version> previous_version = ccf::kv::Version{
      1} /* default: not self-endorsement */)
  {
    ccf::CoseEndorsement e;
    e.endorsement_epoch_begin = ccf::TxID{begin_view, begin_seqno};
    e.endorsement_epoch_end = ccf::TxID{end_view, end_seqno};
    e.previous_version = previous_version;
    return e;
  }

  ccf::CoseEndorsement make_self_endorsement(
    ccf::View begin_view, ccf::SeqNo begin_seqno)
  {
    ccf::CoseEndorsement e;
    e.endorsement_epoch_begin = ccf::TxID{begin_view, begin_seqno};
    // Self-endorsements have neither epoch_end nor previous_version
    e.endorsement_epoch_end = std::nullopt;
    e.previous_version = std::nullopt;
    return e;
  }

  // Test scaffolding ─────────────────────────────────────────────────────

  // Mocks — in-memory canned responses. `unavailable` lets tests
  // simulate "ledger chunk is not yet loadable" by making
  // get_endorsement_at(seq) return nullopt.
  class MockNodeStateAccessor : public ccf::INodeStateAccessor
  {
  public:
    bool part_of_network = true;
    std::optional<ccf::TxID> current_service_from;
    std::optional<ccf::CoseEndorsement> topmost;

    [[nodiscard]] bool is_part_of_network() const override
    {
      return part_of_network;
    }
    std::optional<ccf::TxID> read_current_service_from() override
    {
      return current_service_from;
    }
    std::optional<ccf::CoseEndorsement> read_topmost_endorsement() override
    {
      return topmost;
    }
  };

  class MockHistoricalStateAccessor : public ccf::IHistoricalStateAccessor
  {
  public:
    std::map<ccf::SeqNo, ccf::CoseEndorsement> entries;
    std::set<ccf::SeqNo> unavailable;

    std::optional<ccf::CoseEndorsement> get_endorsement_at(
      ccf::SeqNo seq) override
    {
      if (unavailable.contains(seq))
      {
        return std::nullopt;
      }
      auto it = entries.find(seq);
      if (it == entries.end())
      {
        return std::nullopt;
      }
      return it->second;
    }
  };

  // Fake TaskScheduler — queues immediate and delayed tasks for tests
  // to fire deterministically. Thread-safe for concurrent add_task /
  // add_delayed_task calls (the subsystem may schedule from multiple
  // threads in trigger_extension scenarios); single-threaded for
  // drain methods, which tests call from the main thread.
  class FakeTaskScheduler : public ccf::TaskScheduler
  {
  public:
    std::mutex mtx;
    std::deque<std::function<void()>> immediate;
    std::deque<std::function<void()>> delayed;

    void add_task(std::function<void()> fn) override
    {
      std::lock_guard<std::mutex> g(mtx);
      immediate.push_back(std::move(fn));
    }

    void add_delayed_task(
      std::function<void()> fn, std::chrono::milliseconds /* delay */) override
    {
      std::lock_guard<std::mutex> g(mtx);
      delayed.push_back(std::move(fn));
    }

    [[nodiscard]] size_t pending_immediate_count()
    {
      std::lock_guard<std::mutex> g(mtx);
      return immediate.size();
    }

    [[nodiscard]] size_t pending_delayed_count()
    {
      std::lock_guard<std::mutex> g(mtx);
      return delayed.size();
    }

    // Drain all immediate tasks, calling each. May push new ones.
    void run_immediate()
    {
      while (true)
      {
        std::function<void()> fn;
        {
          std::lock_guard<std::mutex> g(mtx);
          if (immediate.empty())
          {
            return;
          }
          fn = std::move(immediate.front());
          immediate.pop_front();
        }
        fn();
      }
    }

    // Fire all delayed tasks and drain any immediate tasks they enqueue.
    // Returns the number of delayed tasks fired.
    size_t fire_delayed_once()
    {
      std::deque<std::function<void()>> batch;
      {
        std::lock_guard<std::mutex> g(mtx);
        batch = std::move(delayed);
        delayed.clear();
      }
      size_t ran = 0;
      for (auto& fn : batch)
      {
        fn();
        ++ran;
      }
      run_immediate();
      return ran;
    }

    // Loop firing immediate + delayed until both are empty.
    void run_to_completion(size_t safety_cap = 100)
    {
      run_immediate();
      while (pending_delayed_count() > 0 && safety_cap-- > 0)
      {
        fire_delayed_once();
      }
    }
  };

  // ChainBuilder — mints real COSE-signed endorsements via the same
  // cose-rs path production uses. Layout mirrors production:
  //
  //   * Service S_0 self-endorses, producing entry e_0. e_0 has no
  //     epoch_end and no previous_version. Its epoch_begin is the create
  //     TxID of S_0.
  //   * Each subsequent service S_i (i>=1) creates entry e_i whose
  //     endorsing_key is S_i's public key and whose COSE payload is
  //     S_{i-1}'s public key. e_i.epoch_begin equals the previous entry's
  //     epoch_begin if the previous is a self-endorsement, else
  //     next_tx_if_recovery(prev.epoch_end). e_i.epoch_end is one txid
  //     before S_i's create TxID. e_i.previous_version is the kv::Version
  //     at which e_{i-1} was written.
  //   * In production, e_N (the topmost) is what
  //     `read_topmost_endorsement` returns. e_0..e_{N-1} are what
  //     `get_endorsement_at(write_version)` returns. The current
  //     service's public key (in DER) must match e_N's signing key,
  //     which is what `process_link` checks against
  //     `network_identity->get_key_pair()->public_key_der()`.
  //
  // For Test purposes we ignore the "previous_root" semantics — the
  // subsystem doesn't validate it.
  class ChainBuilder
  {
  public:
    std::vector<std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL>> service_keys;
    std::vector<ccf::CoseEndorsement> entries;
    std::vector<ccf::kv::Version> write_versions;
    ccf::kv::Version next_write_version = 1;

    // Add the deepest service in the chain, self-endorsing.
    ChainBuilder& add_self(ccf::TxID begin)
    {
      auto kp = std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(
        ccf::crypto::CurveID::SECP384R1);
      ccf::CoseEndorsement e;
      e.endorsement_epoch_begin = begin;
      e.endorsing_key = kp->public_key_der();
      e.endorsement = sign(*kp, begin, std::nullopt, {}, kp->public_key_der());
      service_keys.push_back(kp);
      entries.push_back(e);
      write_versions.push_back(next_write_version++);
      return *this;
    }

    // Add the next service in the chain, endorsing the prior service's
    // key. `begin` and `end` define this entry's epoch range.
    ChainBuilder& add_next(ccf::TxID begin, ccf::TxID end)
    {
      REQUIRE(!service_keys.empty());
      auto kp = std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(
        ccf::crypto::CurveID::SECP384R1);
      const auto& prev_kp = service_keys.back();
      ccf::CoseEndorsement e;
      e.endorsement_epoch_begin = begin;
      e.endorsement_epoch_end = end;
      e.previous_version = write_versions.back();
      e.endorsing_key = kp->public_key_der();
      e.endorsement = sign(
        *kp,
        begin,
        end,
        std::vector<uint8_t>{0xaa, 0xbb, 0xcc, 0xdd},
        prev_kp->public_key_der());
      service_keys.push_back(kp);
      entries.push_back(e);
      write_versions.push_back(next_write_version++);
      return *this;
    }

    // The current service's public key (DER) — matches the most-recent
    // entry's signing key, which `process_link` checks against
    // `network_identity->get_key_pair()->public_key_der()`.
    [[nodiscard]] std::vector<uint8_t> current_pkey_der() const
    {
      REQUIRE(!service_keys.empty());
      return service_keys.back()->public_key_der();
    }

    [[nodiscard]] std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL>
    current_key_pair() const
    {
      REQUIRE(!service_keys.empty());
      return service_keys.back();
    }

    // TxID at which the current service was created. Synthesised by
    // applying the recovery (view, seqno) increment to the most-recent
    // entry's epoch_end. The subsystem checks the resulting TxID against
    // the last entry's epoch_end via validate_chain_front_connection.
    [[nodiscard]] ccf::TxID synthesised_current_service_from() const
    {
      REQUIRE(!entries.empty());
      const auto& last = entries.back();
      REQUIRE(last.endorsement_epoch_end.has_value());
      return ccf::TxID{
        last.endorsement_epoch_end->view + aft::starting_view_change,
        last.endorsement_epoch_end->seqno + 1};
    }

    // For sources: pop the topmost entry off (it lives in
    // read_topmost_endorsement, not in `historical`).
    ccf::CoseEndorsement topmost_entry() const
    {
      REQUIRE(!entries.empty());
      return entries.back();
    }
    std::map<ccf::SeqNo, ccf::CoseEndorsement> historical_entries() const
    {
      std::map<ccf::SeqNo, ccf::CoseEndorsement> m;
      // All but the topmost.
      for (size_t i = 0; i + 1 < entries.size(); ++i)
      {
        m.emplace(write_versions[i], entries[i]);
      }
      return m;
    }

  private:
    static std::vector<uint8_t> sign(
      ccf::crypto::ECKeyPair_OpenSSL& key,
      const ccf::TxID& begin,
      const std::optional<ccf::TxID>& end,
      const std::vector<uint8_t>& previous_root,
      const std::vector<uint8_t>& payload)
    {
      const auto begin_str = begin.to_str();
      const auto end_str = end.has_value() ? end->to_str() : std::string{};
      auto priv_der = key.private_key_der();
      CoseBuffer key_err;
      auto cose_key =
        CoseKey::from_private(priv_der.data(), priv_der.size(), key_err);
      REQUIRE(cose_key.is_set());

      CoseBuffer out;
      CoseBuffer sign_err;
      auto rc = cose_sign_endorsement(
        cose_key,
        /*iat=*/1700000000,
        reinterpret_cast<const uint8_t*>(begin_str.data()),
        begin_str.size(),
        end.has_value() ? reinterpret_cast<const uint8_t*>(end_str.data()) :
                          nullptr,
        end.has_value() ? end_str.size() : 0,
        previous_root.data(),
        previous_root.size(),
        payload.data(),
        payload.size(),
        out,
        sign_err);
      REQUIRE(rc == 0);
      REQUIRE(out.is_set());
      return out.to_vector();
    }
  };

  // Fixture that owns the mocks, scheduler, and identity so tests can
  // build a subsystem with one call.
  struct SubsystemFixture
  {
    std::shared_ptr<MockNodeStateAccessor> node_state =
      std::make_shared<MockNodeStateAccessor>();
    std::shared_ptr<MockHistoricalStateAccessor> historical =
      std::make_shared<MockHistoricalStateAccessor>();
    std::shared_ptr<FakeTaskScheduler> scheduler =
      std::make_shared<FakeTaskScheduler>();
    std::unique_ptr<ccf::NetworkIdentity> identity;

    SubsystemFixture()
    {
      identity = std::make_unique<ccf::NetworkIdentity>(
        "CN=Test Service",
        ccf::crypto::CurveID::SECP384R1,
        "20240101000000Z",
        365);
    }

    // Replace the identity's key pair so its public key matches the chain
    // tail. Tests must do this BEFORE constructing the subsystem.
    void use_identity_key(
      const std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL>& kp)
    {
      identity->priv_key = kp->private_key_pem();
    }

    std::unique_ptr<ccf::NetworkIdentitySubsystem> make_subsystem()
    {
      return std::make_unique<ccf::NetworkIdentitySubsystem>(
        node_state, historical, identity, scheduler);
    }
  };

  // Populate the mocks from `cb` to model a chain of length N already
  // committed to the ledger and topmost in the current store.
  void wire_chain(
    SubsystemFixture& f,
    const ChainBuilder& cb,
    std::optional<ccf::TxID> current_service_from = std::nullopt)
  {
    f.node_state->current_service_from =
      current_service_from.value_or(cb.synthesised_current_service_from());
    f.node_state->topmost = cb.topmost_entry();
    f.historical->entries = cb.historical_entries();
  }
}

TEST_CASE("is_self_endorsement detects absence of previous_version")
{
  REQUIRE(ccf::is_self_endorsement(make_self_endorsement(2, 10)));
  REQUIRE_FALSE(ccf::is_self_endorsement(make_range_endorsement(3, 11, 3, 20)));
}

TEST_CASE("is_ill_formed detects inverted range")
{
  REQUIRE(ccf::is_ill_formed(make_range_endorsement(3, 20, 3, 10)));
  REQUIRE_FALSE(ccf::is_ill_formed(make_range_endorsement(3, 10, 3, 20)));
  // Self-endorsement has no epoch_end, so it is never ill-formed
  REQUIRE_FALSE(ccf::is_ill_formed(make_self_endorsement(2, 10)));
}

TEST_CASE("verify_endorsements_connected accepts adjacent endorsements")
{
  // older covers [v=2, 10..20]; newer starts at v=3, seqno=21.
  // The view rule is: newer.begin.view - aft::starting_view_change ==
  // older.end.view, and newer.begin.seqno - 1 == older.end.seqno.
  auto older = make_range_endorsement(2, 10, 2, 20);
  auto newer = make_range_endorsement(2 + aft::starting_view_change, 21, 3, 30);

  REQUIRE_NOTHROW(ccf::verify_endorsements_connected(newer, older));
}

TEST_CASE("verify_endorsements_connected rejects view discontinuity")
{
  auto older = make_range_endorsement(2, 10, 2, 20);
  // newer.begin.view should be 2 + starting_view_change; use a wrong value
  auto newer =
    make_range_endorsement(2 + aft::starting_view_change + 1, 21, 3, 30);

  REQUIRE_THROWS_AS(
    ccf::verify_endorsements_connected(newer, older), std::logic_error);
}

TEST_CASE("verify_endorsements_connected rejects seqno gap")
{
  auto older = make_range_endorsement(2, 10, 2, 20);
  // seqno gap: newer.begin.seqno should be 21
  auto newer = make_range_endorsement(2 + aft::starting_view_change, 22, 3, 30);

  REQUIRE_THROWS_AS(
    ccf::verify_endorsements_connected(newer, older), std::logic_error);
}

TEST_CASE("verify_endorsements_connected rejects older with no epoch_end")
{
  ccf::CoseEndorsement older = make_range_endorsement(2, 10, 2, 20);
  older.endorsement_epoch_end = std::nullopt;
  auto newer = make_range_endorsement(2 + aft::starting_view_change, 21, 3, 30);

  REQUIRE_THROWS_AS(
    ccf::verify_endorsements_connected(newer, older), std::logic_error);
}

TEST_CASE(
  "validate_chain_front_connection requires current_service_from to "
  "immediately follow the endorsement")
{
  ccf::CoseEndorsement e = make_range_endorsement(2, 10, 2, 20);

  // current_service_from must have view = 2 + starting_view_change and
  // seqno = 21 to be adjacent.
  ccf::TxID good{2 + aft::starting_view_change, 21};
  REQUIRE_NOTHROW(ccf::validate_chain_front_connection(e, good));

  ccf::TxID bad_seqno{2 + aft::starting_view_change, 22};
  REQUIRE_THROWS_AS(
    ccf::validate_chain_front_connection(e, bad_seqno), std::logic_error);

  ccf::TxID bad_view{3 + aft::starting_view_change, 21};
  REQUIRE_THROWS_AS(
    ccf::validate_chain_front_connection(e, bad_view), std::logic_error);
}

TEST_CASE(
  "validate_chain_front_connection rejects endorsement with no epoch_end")
{
  ccf::CoseEndorsement bad = make_range_endorsement(2, 10, 2, 20);
  bad.endorsement_epoch_end = std::nullopt;

  ccf::TxID after{2 + aft::starting_view_change, 21};
  REQUIRE_THROWS_AS(
    ccf::validate_chain_front_connection(bad, after), std::logic_error);
}

// ────────────────────────────────────────────────────────────────────────
// State-machine tests using Mock{NodeState,HistoricalState}Accessor +
// FakeTaskScheduler + ChainBuilder. Each test wires a synthetic ledger,
// constructs the subsystem, drives the scheduler, and asserts on the
// public state.
// ────────────────────────────────────────────────────────────────────────

TEST_CASE("Bootstrap with self-only chain transitions immediately to Done")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 100});
  f.use_identity_key(cb.current_key_pair());
  // Self-only: topmost IS the self-endorsement, current_service_from
  // matches its epoch_begin.
  f.node_state->current_service_from = {2, 100};
  f.node_state->topmost = cb.topmost_entry();

  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();

  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  auto keys = sub->get_trusted_keys();
  REQUIRE(keys.size() == 1);
  // Current-epoch seqno: empty chain (short-circuited by the
  // seqno >= current_service_from branch).
  REQUIRE(sub->get_cose_endorsements_chain(100)->empty());
  // Older seqno: Done + !has_predecessors → empty chain (pre-history,
  // no historical endorsements will ever cover it).
  REQUIRE(sub->get_cose_endorsements_chain(50)->empty());
}

TEST_CASE("Bootstrap with N-link chain reaches Done with full key map")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  size_t expected_keys = 2; // topmost + current

  SUBCASE("3 links")
  {
    cb.add_next({6, 201}, {6, 400});
    expected_keys = 3;
  }
  SUBCASE("5 links")
  {
    cb.add_next({6, 201}, {6, 400})
      .add_next({8, 401}, {8, 600})
      .add_next({10, 601}, {10, 800});
    expected_keys = 5;
  }

  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);

  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();

  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  REQUIRE(sub->get_trusted_keys().size() == expected_keys);
}

TEST_CASE(
  "Bootstrap exhausts → Partial; trigger_extension when chunk reappears → Done")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  // Predecessor's chunk is missing during the initial fetch.
  f.historical->unavailable.insert(cb.write_versions.at(0));

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();

  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  // Topmost + seeded current-service key.
  REQUIRE(sub->get_trusted_keys().size() == 2);
  // Current-epoch reads succeed with an empty chain.
  REQUIRE(sub->get_cose_endorsements_chain(401)->empty());

  // Chunk reappears; caller triggers extension and the chain heals.
  f.historical->unavailable.clear();
  sub->trigger_extension();
  f.scheduler->run_to_completion();

  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  REQUIRE(sub->get_trusted_keys().size() == 2);
}

TEST_CASE(
  "trigger_extension in non-Partial states is a no-op (status unchanged, "
  "no task scheduled)")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1});
  f.use_identity_key(cb.current_key_pair());
  f.node_state->current_service_from = {2, 1};
  f.node_state->topmost = cb.topmost_entry();

  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);

  REQUIRE(f.scheduler->pending_immediate_count() == 0);
  REQUIRE(f.scheduler->pending_delayed_count() == 0);

  sub->trigger_extension();
  REQUIRE(f.scheduler->pending_immediate_count() == 0);
  REQUIRE(f.scheduler->pending_delayed_count() == 0);
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
}

TEST_CASE("Back-to-back trigger_extension calls schedule at most one new cycle")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  f.historical->unavailable.insert(cb.write_versions.at(0));

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  REQUIRE(f.scheduler->pending_immediate_count() == 0);
  REQUIRE(f.scheduler->pending_delayed_count() == 0);

  // Source still has the chunk unavailable, so the new cycle will not
  // succeed on its first try — it must schedule a retry. Multiple
  // back-to-back trigger calls should fold into the SAME single cycle.
  sub->trigger_extension();
  sub->trigger_extension();
  sub->trigger_extension();

  // Exactly one immediate task was added (the others CAS-failed).
  REQUIRE(f.scheduler->pending_immediate_count() == 1);
  f.scheduler->run_immediate();
  // That task's failed fetch enqueues exactly one delayed retry.
  REQUIRE(f.scheduler->pending_delayed_count() == 1);
}

// ────────────────────────────────────────────────────────────────────────
// Extended coverage: bootstrap waiting cases, multi-step extension,
// Failed transitions, reader semantics, concurrency, stale callbacks.
// ────────────────────────────────────────────────────────────────────────

TEST_CASE("Bootstrap waits for is_part_of_network then proceeds")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1});
  f.use_identity_key(cb.current_key_pair());
  f.node_state->current_service_from = ccf::TxID{2, 1};
  f.node_state->topmost = cb.topmost_entry();
  f.node_state->part_of_network = false;

  auto sub = f.make_subsystem();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  // A delayed retry_first_fetch should have been scheduled.
  REQUIRE(f.scheduler->pending_delayed_count() == 1);

  // Fire it: still not part of network → another retry queued.
  f.scheduler->fire_delayed_once();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(f.scheduler->pending_delayed_count() == 1);

  // Become ready; next firing should bootstrap to Done.
  f.node_state->part_of_network = true;
  f.scheduler->fire_delayed_once();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
}

// Readers must be safe to call before fetch_first has produced anything
// useful: no nullopt-deref of current_service_from, no iterator-deref of
// empty trusted_keys / endorsements, and trigger_extension is a no-op
// (the initial cycle still holds fetch_active).
TEST_CASE("Readers safe immediately after construction (nothing fetched yet)")
{
  SubsystemFixture f;
  f.node_state->part_of_network = false;
  auto sub = f.make_subsystem();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  REQUIRE_FALSE(sub->get_cose_endorsements_chain(0).has_value());
  REQUIRE_FALSE(sub->get_cose_endorsements_chain(123).has_value());
  REQUIRE(sub->get_trusted_identity_for(0) == nullptr);
  REQUIRE(sub->get_trusted_identity_for(999) == nullptr);
  REQUIRE(sub->get_trusted_keys().empty());

  // trigger_extension folds into the active initial cycle (CAS on
  // fetch_active fails), so no new task is scheduled.
  const auto immediate_before = f.scheduler->pending_immediate_count();
  sub->trigger_extension();
  REQUIRE(f.scheduler->pending_immediate_count() == immediate_before);
}

TEST_CASE("Bootstrap waits for current_service_from then proceeds")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1});
  f.use_identity_key(cb.current_key_pair());
  // part_of_network=true (default) but no current_service_from yet
  f.node_state->topmost = cb.topmost_entry();

  auto sub = f.make_subsystem();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(f.scheduler->pending_delayed_count() == 1);

  f.node_state->current_service_from = ccf::TxID{2, 1};
  f.scheduler->fire_delayed_once();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
}

TEST_CASE("Bootstrap waits for topmost endorsement entry then proceeds")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1});
  f.use_identity_key(cb.current_key_pair());
  f.node_state->current_service_from = ccf::TxID{2, 1};
  // topmost is unset

  auto sub = f.make_subsystem();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(f.scheduler->pending_delayed_count() == 1);

  f.node_state->topmost = cb.topmost_entry();
  f.scheduler->fire_delayed_once();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
}

TEST_CASE("retry_first_fetch respects MAX_FETCH_ATTEMPTS budget")
{
  SubsystemFixture f;
  // Source never becomes ready: retry_first_fetch loops until it
  // exhausts the budget, then ends the cycle in Partial without
  // anything to serve. trigger_extension can then dispatch a fresh
  // fetch_first to try again.
  f.node_state->part_of_network = false;

  auto sub = f.make_subsystem();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  // One delayed retry queued after the synchronous fetch_first in the ctor.
  REQUIRE(f.scheduler->pending_delayed_count() == 1);

  // Fire the budget-minus-two times: 28 more retries; counter goes from
  // 1 → 29, still under MAX_FETCH_ATTEMPTS == 30. Each firing should
  // re-queue another delayed task.
  for (int i = 0; i < 28; ++i)
  {
    REQUIRE(f.scheduler->fire_delayed_once() == 1);
    REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
    REQUIRE(f.scheduler->pending_delayed_count() == 1);
  }

  // 30th firing trips the budget. complete_partial ends the cycle in
  // Partial; no further task is queued.
  f.scheduler->fire_delayed_once();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(f.scheduler->pending_delayed_count() == 0);

  // Readers return nothing meaningful — current_service_from never
  // resolved.
  REQUIRE_FALSE(sub->get_cose_endorsements_chain(50).has_value());
  REQUIRE(sub->get_trusted_identity_for(50) == nullptr);
  REQUIRE(sub->get_trusted_keys().empty());

  // trigger_extension dispatches a fresh fetch_first. Source is still
  // not ready, so a new delayed-retry cycle begins.
  sub->trigger_extension();
  REQUIRE(f.scheduler->pending_immediate_count() == 1);
  f.scheduler->run_immediate();
  REQUIRE(f.scheduler->pending_delayed_count() == 1);
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
}

TEST_CASE("retry_first_fetch budget reset by successful progress")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());

  // Source not ready initially.
  f.node_state->part_of_network = false;

  auto sub = f.make_subsystem();
  // Burn 5 retries.
  for (int i = 0; i < 5; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  // Service comes up; wire the chain.
  f.node_state->part_of_network = true;
  wire_chain(f, cb);
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
}

TEST_CASE(
  "retry_first_fetch exhausted with service info set but no topmost → "
  "Partial; readers return nullopt instead of false 'pre-history'")
{
  SubsystemFixture f;
  // current_service_from is resolvable, but read_topmost_endorsement
  // returns nullopt forever. Exhaustion → complete_partial → Partial
  // (current_service_from is set). has_predecessors stays false (we
  // never read the topmost), but the reader must distinguish this
  // from a confirmed self-only chain and return nullopt for any older
  // seqno.
  f.node_state->current_service_from = ccf::TxID{2, 100};
  // No topmost wired.
  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  // Current-epoch seqno: empty chain (current service identity covers).
  auto current_chain = sub->get_cose_endorsements_chain(100);
  REQUIRE(current_chain.has_value());
  REQUIRE(current_chain->empty());

  // Older seqno: nullopt (we don't know if there's a chain; caller
  // should trigger_extension and retry).
  auto older = sub->get_cose_endorsements_chain(50);
  REQUIRE_FALSE(older.has_value());

  // trusted_keys contains the seeded current-service key.
  auto keys = sub->get_trusted_keys();
  REQUIRE(keys.size() == 1);
  REQUIRE(keys.count(100) == 1);
}

TEST_CASE("Partial → Partial: re-trigger that also exhausts")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  f.historical->unavailable.insert(cb.write_versions.at(0));

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  const auto trusted_before = sub->get_trusted_keys();

  // Re-trigger while chunk is STILL unavailable.
  sub->trigger_extension();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->run_immediate();
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();

  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(sub->get_trusted_keys().size() == trusted_before.size());
}

TEST_CASE("Multi-step extension: one trigger heals 3 missing predecessors")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1})
    .add_next({2, 1}, {4, 200})
    .add_next({6, 201}, {6, 400})
    .add_next({8, 401}, {8, 600});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  // Make ALL predecessors of the topmost unavailable. Only the topmost
  // (in source.topmost) is initially reachable.
  f.historical->unavailable = {
    cb.write_versions.at(0), cb.write_versions.at(1), cb.write_versions.at(2)};

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(sub->get_trusted_keys().size() == 2); // topmost + current

  // Make ALL predecessors available; one trigger should walk back through
  // every one of them and finalise Done.
  f.historical->unavailable.clear();
  sub->trigger_extension();
  f.scheduler->run_to_completion();

  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  REQUIRE(sub->get_trusted_keys().size() == 4);
}

TEST_CASE("Failed: bad signature on topmost detected during bootstrap")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);

  // Tamper the topmost's signature. process_link verifies it during
  // the synchronous initial fetch, throws, fail_fetching transitions
  // to Failed and re-throws — escaping the constructor since the
  // all-available chain runs to completion synchronously.
  REQUIRE(f.node_state->topmost.has_value());
  f.node_state->topmost->endorsement.back() ^= 0xFF;

  REQUIRE_THROWS_AS({ auto sub = f.make_subsystem(); }, std::exception);
}

TEST_CASE("Failed: tampered epoch range detected during extension cycle")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200}).add_next({6, 201}, {6, 400});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  auto mid_wv = cb.write_versions.at(1);
  f.historical->unavailable.insert(mid_wv);

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  // Restore the chunk but tamper the epoch_end on the table side.
  // validate_fetched_endorsement compares the COSE header range
  // against the table fields; mismatch → throw → Failed.
  f.historical->unavailable.clear();
  f.historical->entries.at(mid_wv).endorsement_epoch_end = ccf::TxID{99, 99999};

  sub->trigger_extension();
  REQUIRE_THROWS_AS(f.scheduler->run_to_completion(), std::exception);
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Failed);
}

TEST_CASE("Failed: chain link broken (wrong endorsing_key) during bootstrap")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200}).add_next({6, 201}, {6, 400});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);

  // Replace the middle entry's endorsing_key with a stranger; the
  // actual signature was made with the original key, so verification
  // fails. Throw escapes the constructor.
  auto mid_wv = cb.write_versions.at(1);
  auto stranger = std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::CurveID::SECP384R1);
  f.historical->entries.at(mid_wv).endorsing_key = stranger->public_key_der();

  REQUIRE_THROWS_AS({ auto sub = f.make_subsystem(); }, std::exception);
}

TEST_CASE(
  "Failed: self-endorsement at unexpected seqno detected during bootstrap")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1});
  f.use_identity_key(cb.current_key_pair());
  // Advertise current_service_from at a different seqno than the
  // self-endorsement's epoch_begin.
  f.node_state->current_service_from = ccf::TxID{2, 99};
  f.node_state->topmost = cb.topmost_entry();

  REQUIRE_THROWS_AS({ auto sub = f.make_subsystem(); }, std::exception);
}

TEST_CASE("Reader: get_cose_endorsements_chain returns nullopt while waiting")
{
  SubsystemFixture f;
  // Source is left unconfigured: bootstrap loops in retry_first_fetch.
  // The subsystem starts in Partial and stays there; reads succeed but
  // can't resolve any seqno because no chain has been built yet.
  f.node_state->part_of_network = false;
  auto sub = f.make_subsystem();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  auto chain = sub->get_cose_endorsements_chain(123);
  REQUIRE_FALSE(chain.has_value());
}

// In Failed, readers must not throw — they serve whatever was validated
// before the failure (the validator rejected the next link without
// committing). Caller checks status to decide what to do.
TEST_CASE("Reader: all three readers serve validated prefix in Failed")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200}).add_next({6, 201}, {6, 400});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  auto mid_wv = cb.write_versions.at(1);
  f.historical->unavailable.insert(mid_wv);

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  // Snapshot the validated prefix before tampering.
  const auto pre_keys = sub->get_trusted_keys();

  f.historical->unavailable.clear();
  f.historical->entries.at(mid_wv).endorsement_epoch_end = ccf::TxID{99, 99999};
  sub->trigger_extension();
  REQUIRE_THROWS_AS(f.scheduler->run_to_completion(), std::exception);
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Failed);

  // Readers still serve. trusted_keys preserved exactly as before;
  // chain reader returns nullopt for older-seqno (would have needed
  // the missing/tainted predecessor) or the validated prefix for a
  // seqno already covered.
  REQUIRE(sub->get_trusted_keys() == pre_keys);
  REQUIRE_FALSE(sub->get_cose_endorsements_chain(50).has_value());
}

TEST_CASE("Reader: empty chain for current-epoch seqno in Done")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  // current_service_from = synthesised = view 6, seqno 201
  auto chain = sub->get_cose_endorsements_chain(500);
  REQUIRE(chain.has_value());
  REQUIRE(chain->empty());
}

TEST_CASE("Reader: empty chain for pre-history seqno in Done")
{
  // Construct a chain whose earliest endorsement has begin.seqno > 1, then
  // request seqno 0 (pre-history). chain_complete logic returns empty.
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 100}).add_next({2, 100}, {4, 500});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  auto chain = sub->get_cose_endorsements_chain(50);
  REQUIRE(chain.has_value());
  REQUIRE(chain->empty());
}

TEST_CASE("Reader: nullopt for uncovered seqno in Partial")
{
  SubsystemFixture f;
  ChainBuilder cb;
  // Pick a self-endorsement at seqno 100 so the topmost ends up with
  // earliest_endorsed_seq = 100 and a query at seqno 50 is genuinely
  // below the partial chain.
  cb.add_self({2, 100}).add_next({2, 100}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  f.historical->unavailable.insert(cb.write_versions.at(0));

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);

  // earliest_endorsed_seq is the topmost's begin.seqno = 100.
  // A request strictly below that returns nullopt (caller may trigger
  // extension).
  REQUIRE_FALSE(sub->get_cose_endorsements_chain(50).has_value());
  // A request inside the topmost epoch returns a non-empty chain.
  auto chain = sub->get_cose_endorsements_chain(150);
  REQUIRE(chain.has_value());
  REQUIRE(chain->size() == 1);
}

TEST_CASE("Reader: get_trusted_identity_for boundary semantics")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200}).add_next({6, 201}, {6, 400});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);

  // trusted_keys are at seqnos {1, 201, 401}
  // Below the earliest → nullptr
  REQUIRE(sub->get_trusted_identity_for(0) == nullptr);
  // Exact boundary returns the key at that seqno
  REQUIRE(sub->get_trusted_identity_for(1) != nullptr);
  // Between boundaries: returns the most-recent <= seqno
  REQUIRE(sub->get_trusted_identity_for(100) != nullptr);
  REQUIRE(sub->get_trusted_identity_for(200) != nullptr);
  REQUIRE(sub->get_trusted_identity_for(201) != nullptr);
  // Far above last boundary → returns the most-recent (current)
  REQUIRE(sub->get_trusted_identity_for(1000000) != nullptr);
}

TEST_CASE("Reader: get_trusted_keys returns partial map in Partial")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1})
    .add_next({2, 1}, {4, 200})
    .add_next({6, 201}, {6, 400})
    .add_next({8, 401}, {8, 600});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  // Make all but the topmost unavailable.
  f.historical->unavailable = {
    cb.write_versions.at(0), cb.write_versions.at(1), cb.write_versions.at(2)};

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  // Only topmost + current = 2 entries; the doxygen note on
  // get_trusted_keys() promises this exact behaviour.
  REQUIRE(sub->get_trusted_keys().size() == 2);
}

TEST_CASE("Concurrent threads triggering all fold into one cycle")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);
  f.historical->unavailable.insert(cb.write_versions.at(0));

  auto sub = f.make_subsystem();
  for (int i = 0; i < 30; ++i)
  {
    f.scheduler->fire_delayed_once();
  }
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Partial);
  REQUIRE(f.scheduler->pending_immediate_count() == 0);

  std::vector<std::thread> threads;
  threads.reserve(16);
  for (int i = 0; i < 16; ++i)
  {
    threads.emplace_back([&] { sub->trigger_extension(); });
  }
  for (auto& t : threads)
  {
    t.join();
  }
  // CAS gate guarantees exactly one cycle started.
  REQUIRE(f.scheduler->pending_immediate_count() == 1);
}

TEST_CASE("Done is terminal: no tasks queued after reaching Done")
{
  SubsystemFixture f;
  ChainBuilder cb;
  cb.add_self({2, 1}).add_next({2, 1}, {4, 200});
  f.use_identity_key(cb.current_key_pair());
  wire_chain(f, cb);

  auto sub = f.make_subsystem();
  f.scheduler->run_to_completion();
  REQUIRE(sub->endorsements_fetching_status() == ccf::FetchStatus::Done);
  REQUIRE(f.scheduler->pending_immediate_count() == 0);
  REQUIRE(f.scheduler->pending_delayed_count() == 0);
}
