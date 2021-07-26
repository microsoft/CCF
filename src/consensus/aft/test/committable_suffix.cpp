// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "test_common.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <doctest/doctest.h>

auto hooks = std::make_shared<kv::ConsensusHookPtrs>();

using AllSigsStore = aft::LoggingStubStoreSig;
using AllSigsAdaptor = aft::Adaptor<AllSigsStore>;

std::shared_ptr<std::vector<uint8_t>> make_ledger_entry(
  const aft::Term term, const aft::Index idx)
{
  const auto s = fmt::format("Ledger entry @{}.{}", term, idx);
  auto e = std::make_shared<std::vector<uint8_t>>(s.begin(), s.end());

  // Each entry is so large that it produces a single AppendEntries, there are
  // never multiple combined into a single AppendEntries
  e->resize(TRaft::append_entries_size_limit);

  return e;
}

void keep_messages_for(
  const ccf::NodeId& target,
  aft::ChannelStubProxy::MessageList& messages,
  std::optional<size_t> max_to_keep = std::nullopt)
{
  auto it = messages.begin();
  size_t kept = 0;
  while (it != messages.end())
  {
    if (
      it->first != target || (max_to_keep.has_value() && kept >= *max_to_keep))
    {
      it = messages.erase(it);
    }
    else
    {
      ++it;
      ++kept;
    }
  }
}

void keep_first_for(
  const ccf::NodeId& target,
  aft::ChannelStubProxy::MessageList& messages,
  std::optional<size_t> max_to_keep = std::nullopt)
{
  keep_messages_for(target, messages, 1);
}

#define TEST_DECLARE_NODE(N) \
  ccf::NodeId node_id##N(#N); \
  auto store##N = std::make_shared<AllSigsStore>(node_id##N); \
  TRaft r##N( \
    ConsensusType::CFT, \
    std::make_unique<AllSigsAdaptor>(store##N), \
    std::make_unique<aft::LedgerStubProxy>(node_id##N), \
    std::make_shared<aft::ChannelStubProxy>(), \
    std::make_shared<aft::StubSnapshotter>(), \
    nullptr, \
    nullptr, \
    cert, \
    std::make_shared<aft::State>(node_id##N), \
    nullptr, \
    nullptr, \
    nullptr, \
    request_timeout, \
    election_timeout, \
    election_timeout); \
  initial_config[node_id##N] = {}; \
  nodes[node_id##N] = &r##N; \
  auto channels##N = channel_stub_proxy(r##N);

/**
  Summary of the behaviour this test aims to explore (for implementation reasons
  the indices in the actual test don't match those in this comment, but the
  logical relationships are the same):

  - Produce an initial state where A is primary in term 1 of a 5-node network,
    has mixed success replicating its entries. Local commit index is marked by
    []. True commit index is the highest of these, [1.2].
    A:  1.1 [1.2] 1.3
    B: [1.1] 1.2  1.3
    C: [1.1] 1.2
    D: [1.1]
    E: [1.1]

  - Intuitively, B and C are responsible for persisting 1.2, although they don't
    know this locally.

  - Node A dies. Node B becomes primary, and creates some tail junk that no-one
    else sees. It makes no commit progress. Crucially this is committable (as
    all of these indices are), so B is reluctant to discard the entries in term
    2, and 1.3, though all _could_ be discarded.
    A:  1.1 [1.2] 1.3 (DEAD)
    B: [1.1] 1.2  1.3  2.4  2.5
    C: [1.1] 1.2
    D: [1.1]
    E: [1.1]

  - Node C doesn't hear from B for long enough, and becomes primary. Its
    AppendEntries are regularly lost. Eventually a heartbeat ("I'm at 1.2")
    reaches Node B, which responds with a NACK ("I don't accept that tail").
    Node C responds to that NACK with a better AppendEntries, which _should_
    bring Node B back to the committed level, and forward to wherever C is.
    However, under the current implementation, this AppendEntries may
    actually cause B to roll back further than is safe, losing the committed
    state.
    C->B: AE [1.2, 1.2)
    B->C: AER NACK 1.1 (B's commit index)
    C->B: AE [1.1, 1.1) (Large entries mean this is only a partial catchup)
    B: Rolls back to 1.1

    B: [1.1]
    C: [1.1] 1.2
    D: [1.1]
    E: [1.1]

  - At this point a committed index (1.2) is no longer present on a majority of
    nodes. While C is unlikely to advertise it (fancy election rules mean
    they're waiting for commit at 1.2) and will continue to share it, its
    possible for C to die here and B, D, or E to win an election and proceed
    without this committed suffix, forking/overwriting 1.2 with 4.2.
 */
DOCTEST_TEST_CASE("Retention of dead leader's commit")
{
  // Single configuration has all nodes, fully connected
  aft::Configuration::Nodes initial_config;

  std::map<ccf::NodeId, TRaft*> nodes;

  // Network contains 5 nodes
  TEST_DECLARE_NODE(A);
  TEST_DECLARE_NODE(B);
  TEST_DECLARE_NODE(C);
  TEST_DECLARE_NODE(D);
  TEST_DECLARE_NODE(E);

  {
    rA.add_configuration(0, initial_config);
    rB.add_configuration(0, initial_config);
    rC.add_configuration(0, initial_config);
    rD.add_configuration(0, initial_config);
    rE.add_configuration(0, initial_config);
  }

  DOCTEST_INFO("Node A is the initial primary");
  {
    rA.periodic(election_timeout);

    // Dispatch RequestVotes
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idA, channelsA->messages));

    // Dispatch responses
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB, channelsB->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC, channelsC->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idE, channelsE->messages));

    DOCTEST_REQUIRE(rA.is_primary());
    DOCTEST_REQUIRE(rA.get_term() == 1);

    // Dispatch initial AppendEntries
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idA, channelsA->messages));

    // Dispatch initial AppendEntriesResponses
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB, channelsB->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC, channelsC->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idE, channelsE->messages));

    DOCTEST_REQUIRE(rA.is_primary());
    DOCTEST_REQUIRE(rA.get_term() == 1);
  }

  DOCTEST_INFO("Entry at 1.1 is received by all nodes");
  {
    auto entry = make_ledger_entry(1, 1);
    rA.replicate(kv::BatchVector{{1, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 1);
    DOCTEST_REQUIRE(rA.get_commit_idx() == 0);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    // Dispatch AppendEntries
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idA, channelsA->messages));

    // All nodes have this
    DOCTEST_REQUIRE(rB.get_last_idx() == 1);
    DOCTEST_REQUIRE(rC.get_last_idx() == 1);
    DOCTEST_REQUIRE(rD.get_last_idx() == 1);
    DOCTEST_REQUIRE(rE.get_last_idx() == 1);

    // Dispatch AppendEntriesResponses
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB, channelsB->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC, channelsC->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idE, channelsE->messages));

    // Node A now knows this is committed
    DOCTEST_REQUIRE(rA.get_commit_idx() == 1);
  }

  DOCTEST_INFO(
    "Entries at 1.2, 1.3, and 1.4 are received by a majority, and become "
    "committed");
  {
    auto entry = make_ledger_entry(1, 2);
    rA.replicate(kv::BatchVector{{2, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 2);
    DOCTEST_REQUIRE(rA.get_commit_idx() == 1);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    entry = make_ledger_entry(1, 3);
    rA.replicate(kv::BatchVector{{3, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 3);
    DOCTEST_REQUIRE(rA.get_commit_idx() == 1);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    entry = make_ledger_entry(1, 4);
    rA.replicate(kv::BatchVector{{4, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 4);
    DOCTEST_REQUIRE(rA.get_commit_idx() == 1);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    {
      DOCTEST_INFO("Delete the AppendEntries for D and E");
      auto it = channelsA->messages.begin();
      while (it != channelsA->messages.end())
      {
        auto [to, _] = *it;
        if (to == node_idD || to == node_idE)
        {
          it = channelsA->messages.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }

    DOCTEST_REQUIRE(6 == dispatch_all(nodes, node_idA, channelsA->messages));

    // NB: AppendEntriesResponses are not dispatched yet. So 1.4 is technically
    // committed, but nobody knows this yet
  }

  DOCTEST_INFO(
    "Entry at 1.5 is received by only Node B, and is not "
    "committed");
  {
    auto entry = make_ledger_entry(1, 5);
    rA.replicate(kv::BatchVector{{5, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 5);
    // Size limit was reached, so periodic is not needed
    // rB.periodic(request_timeout);

    {
      DOCTEST_INFO("Delete the AppendEntries for C, D and E");
      auto it = channelsA->messages.begin();
      while (it != channelsA->messages.end())
      {
        auto [to, _] = *it;
        if (to == node_idC || to == node_idD || to == node_idE)
        {
          it = channelsA->messages.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }

    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
        nodes, node_idA, channelsA->messages, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.prev_idx == 4);
          DOCTEST_REQUIRE(msg.idx == 5);
        }));

    // Dispatch AppendEntriesResponses (including those from earlier)
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idB, channelsB->messages));
    DOCTEST_REQUIRE(3 == dispatch_all(nodes, node_idC, channelsC->messages));
    DOCTEST_REQUIRE(0 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(0 == dispatch_all(nodes, node_idE, channelsE->messages));

    // Node A now knows that 1.4 is committed
    DOCTEST_REQUIRE(rA.get_commit_idx() == 4);

    // Nodes B and C have this commit index, and are responsible for persisting
    // it
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_commit_idx());
    DOCTEST_REQUIRE(rC.get_last_idx() >= rA.get_commit_idx());
  }

  DOCTEST_INFO("Node A dies");
  // Don't do anything with Node A from here

  DOCTEST_INFO("Node B becomes primary");
  {
    rB.periodic(election_timeout);

    // Dispatch RequestVotes
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idB, channelsB->messages));

    // Dispatch responses
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC, channelsC->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idE, channelsE->messages));

    DOCTEST_REQUIRE(rB.is_primary());
    DOCTEST_REQUIRE(rB.get_term() == 2);
  }

  DOCTEST_INFO("Node B writes some entries, though they are lost");
  {
    auto entry = make_ledger_entry(2, 6);
    rB.replicate(kv::BatchVector{{6, entry, true, hooks}}, 2);
    DOCTEST_REQUIRE(rB.get_last_idx() == 6);

    entry = make_ledger_entry(2, 7);
    rB.replicate(kv::BatchVector{{7, entry, true, hooks}}, 2);
    DOCTEST_REQUIRE(rB.get_last_idx() == 7);

    // Size limit was reached, so periodic is not needed
    // rB.periodic(request_timeout);

    // All those AppendEntries (including the initial ones from winning an
    // election) are lost - this is a dead suffix known only by B.
    channelsB->messages.clear();

    // The key features is that B is one of the quorum responsible for
    // persistence of 1.4, despites its commit index not being as high as 1.4
    DOCTEST_REQUIRE(rB.get_commit_idx() < rA.get_commit_idx());
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_commit_idx());
  }

  DOCTEST_INFO("Node C wins an election");
  {
    rC.periodic(election_timeout);

    // Dispatch RequestVotes
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idC, channelsC->messages));

    // Dispatch responses
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB, channelsB->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idE, channelsE->messages));

    DOCTEST_REQUIRE(rC.is_primary());
    DOCTEST_REQUIRE(rC.get_term() == 3);

    DOCTEST_REQUIRE(rB.get_last_idx() == 7);
    DOCTEST_REQUIRE(rC.get_last_idx() == 4);

    // The early AppendEntries that C tries to send are lost
    rC.periodic(request_timeout);
    channelsC->messages.clear();

    DOCTEST_REQUIRE(rB.get_last_idx() == 7);

    DOCTEST_REQUIRE(rB.get_commit_idx() < rA.get_commit_idx());
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_commit_idx());
  }

  DOCTEST_REQUIRE("Node C produces 3.5, 3.6, and 3.7");
  {
    auto entry = make_ledger_entry(3, 5);
    rC.replicate(kv::BatchVector{{5, entry, true, hooks}}, 3);
    DOCTEST_REQUIRE(rC.get_last_idx() == 5);

    entry = make_ledger_entry(3, 6);
    rC.replicate(kv::BatchVector{{6, entry, true, hooks}}, 3);
    DOCTEST_REQUIRE(rC.get_last_idx() == 6);

    entry = make_ledger_entry(3, 7);
    rC.replicate(kv::BatchVector{{7, entry, true, hooks}}, 3);
    DOCTEST_REQUIRE(rC.get_last_idx() == 7);

    // The early AppendEntries that describe this are lost
    rC.periodic(request_timeout);
    channelsC->messages.clear();

    // Heartbeat AppendEntries are eventually produced
    rC.periodic(request_timeout);

    // Repeatedly send only the first AppendEntries to B, and process its
    // response, until it has rolled back
    const auto tail_of_b = rB.get_last_idx();
    size_t iterations = 0;
    const size_t max_iterations =
      rC.get_last_idx(); // Don't repeat indefinitely
    while (tail_of_b == rB.get_last_idx() && iterations++ < max_iterations)
    {
      // Only the first AppendEntries to B is kept, all other
      // AppendEntries are lost
      keep_first_for(node_idB, channelsC->messages);
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC, channelsC->messages));

      DOCTEST_REQUIRE(
        1 ==
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
          nodes, node_idB, channelsB->messages, [&](const auto& msg) {
            // B NACKs, until it accepts a rollback
            if (tail_of_b == rB.get_last_idx())
            {
              DOCTEST_REQUIRE(
                msg.success == aft::AppendEntriesResponseType::FAIL);
            }
            else
            {
              DOCTEST_REQUIRE(
                msg.success == aft::AppendEntriesResponseType::OK);
            }
          }));
    }

    DOCTEST_REQUIRE(rB.get_last_idx() != tail_of_b);

    // B must still be holding the committed index it holds from A
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_commit_idx());

    // B's term history must match the current primary's
    DOCTEST_REQUIRE(rB.get_last_idx() <= rC.get_last_idx());
    DOCTEST_REQUIRE(
      rB.get_term_history(rB.get_last_idx()) ==
      rC.get_term_history(rB.get_last_idx()));
  }
}

// TODO: What if both nodes have multiple terms after their agreement index?
// Think I can actually trigger this in a 3-node network, where the 3rd node
// is purely there to trigger elections (that it loses), and cause the other
// nodes to advance terms, but they never talk to each other and never make
// commit progress via the 3rd.
DOCTEST_TEST_CASE("Multi-term divergence")
{
  // Single configuration has all nodes, fully connected
  aft::Configuration::Nodes initial_config;

  std::map<ccf::NodeId, TRaft*> nodes;

  // Network contains 3 nodes
  TEST_DECLARE_NODE(A);
  TEST_DECLARE_NODE(B);
  TEST_DECLARE_NODE(C);

  {
    rA.add_configuration(0, initial_config);
    rB.add_configuration(0, initial_config);
    rC.add_configuration(0, initial_config);
  }

  {
    DOCTEST_INFO(
      "Node A is the initial primary, and produces some entries that are "
      "committed and universally known to be committed");
    rA.periodic(election_timeout);

    // Initial election
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));

    DOCTEST_REQUIRE(rA.is_primary());
    DOCTEST_REQUIRE(rA.get_term() == 1);

    // Election-triggered heartbeats
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));

    auto entry = make_ledger_entry(1, 1);
    rA.replicate(kv::BatchVector{{1, entry, true, hooks}}, 1);
    entry = make_ledger_entry(1, 2);
    rA.replicate(kv::BatchVector{{2, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 2);
    DOCTEST_REQUIRE(rA.get_commit_idx() == 0);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    // Dispatch AppendEntries
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idC));

    // All nodes have this
    DOCTEST_REQUIRE(rA.get_last_idx() == 2);
    DOCTEST_REQUIRE(rB.get_last_idx() == 2);
    DOCTEST_REQUIRE(rC.get_last_idx() == 2);

    // And primary knows it is committed
    DOCTEST_REQUIRE(rA.get_commit_idx() == 2);

    // After a periodic heartbeat
    rA.periodic(request_timeout);
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));

    // All nodes know that this is committed
    DOCTEST_REQUIRE(rA.get_commit_idx() == 2);
    DOCTEST_REQUIRE(rB.get_commit_idx() == 2);
    DOCTEST_REQUIRE(rC.get_commit_idx() == 2);

    // Node A produces an additional entry that A and B have, and an additional
    // entry that only A has
    entry = make_ledger_entry(1, 3);
    rA.replicate(kv::BatchVector{{3, entry, true, hooks}}, 1);
    keep_messages_for(node_idB, channelsA->messages);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idA));

    entry = make_ledger_entry(1, 4);
    rA.replicate(kv::BatchVector{{4, entry, true, hooks}}, 1);
    channelsA->messages.clear();
    channelsB->messages.clear();

    DOCTEST_REQUIRE(rA.get_last_idx() == 4);
    DOCTEST_REQUIRE(rB.get_last_idx() == 3);
    DOCTEST_REQUIRE(rC.get_last_idx() == 2);

    // Commit did not advance, though 3 is technically committed and will be
    // persisted from here
    DOCTEST_REQUIRE(rA.get_commit_idx() == 2);
    DOCTEST_REQUIRE(rB.get_commit_idx() == 2);
    DOCTEST_REQUIRE(rC.get_commit_idx() == 2);
  }

  auto create_term_on = [&](bool primary_is_a, size_t num_entries) {
    const auto& primary_id = primary_is_a ? node_idA : node_idB;
    auto& primary = primary_is_a ? rA : rB;
    auto& channels_primary = primary_is_a ? channelsA : channelsB;

    // Drop anything old
    channels_primary->messages.clear();
    channelsC->messages.clear();

    // If C is in an older term, it gets a heartbeat to join this primary's
    // term, but nothing more
    if (rC.get_term() < primary.get_term())
    {
      primary.periodic(request_timeout);
      keep_messages_for(node_idC, channels_primary->messages);
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, primary_id));
      channelsC->messages.clear();
    }

    DOCTEST_REQUIRE(rC.get_term() >= primary.get_term());

    // Node C times out and starts election
    rC.periodic(election_timeout);
    const auto c_term = rC.get_term();

    // Intended primary sees this and votes against, but advances to this term
    keep_messages_for(primary_id, channelsC->messages);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK<aft::RequestVoteResponse>(
        nodes, primary_id, [](const aft::RequestVoteResponse& rvr) {
          DOCTEST_REQUIRE(rvr.vote_granted == false);
        }));
    DOCTEST_REQUIRE(primary.get_term() == c_term);

    // Intended primary times out and starts election
    primary.periodic(election_timeout);

    // RequestVote is only sent to Node C
    keep_messages_for(node_idC, channels_primary->messages);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, primary_id));

    // Node C votes in favour
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK<aft::RequestVoteResponse>(
        nodes, node_idC, [](const aft::RequestVoteResponse& rvr) {
          DOCTEST_REQUIRE(rvr.vote_granted == true);
        }));

    // That's sufficient to win this election
    DOCTEST_REQUIRE(primary.is_primary());

    const auto start_idx = primary.get_last_idx();
    for (auto idx = start_idx + 1; idx <= start_idx + num_entries; ++idx)
    {
      auto entry = make_ledger_entry(primary.get_term(), idx);
      primary.replicate(
        kv::BatchVector{{idx, entry, true, hooks}}, primary.get_term());
    }

    // All related AppendEntries are lost
    channels_primary->messages.clear();
  };

  // For several terms, we randomly choose a primary and have them create an
  // additional suffix term. This produces unique logs on each node, like the
  // following:
  //
  // Index:   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
  // ------------------------------------------------------------------
  // TermA:   1   1   1   1   3   3   3   3   3   9  13  15  15  15  15
  // TermB:   1   1   1   5   5   5   7   7   7   7  11  17  17  17  17
  // TermC:   1   1
  const auto num_terms = 10;
  for (size_t i = 0; i < num_terms; ++i)
  {
    create_term_on(rand() % 2 == 0, rand() % 5 + 1);
  }

  // Nodes A and B now have long, distinct, multi-term non-committed suffixes.
  // Node C has not advanced its log at all
  DOCTEST_REQUIRE(rA.get_commit_idx() == 2);
  DOCTEST_REQUIRE(rB.get_commit_idx() == 2);
  DOCTEST_REQUIRE(rC.get_commit_idx() == 2);

  DOCTEST_REQUIRE(rA.get_last_idx() > 4);
  DOCTEST_REQUIRE(rB.get_last_idx() > 3);
  DOCTEST_REQUIRE(rC.get_last_idx() == 2);

  DOCTEST_REQUIRE(rA.get_term() != rB.get_term());
  DOCTEST_REQUIRE(
    rA.get_term_history(rA.get_last_idx()) !=
    rB.get_term_history(rB.get_last_idx()));

  {
    // Small sanity check - its not as simple as one is a prefix of the other
    const auto common_last_idx = std::min(rA.get_last_idx(), rB.get_last_idx());
    const auto history_on_A = rA.get_term_history(common_last_idx);
    const auto history_on_B = rB.get_term_history(common_last_idx);
    DOCTEST_REQUIRE(history_on_A != history_on_B);

    // In fact they diverge almost immediately
    DOCTEST_REQUIRE(history_on_A[1] != history_on_B[1]);
  }

  {
    channelsA->messages.clear();
    channelsB->messages.clear();
    channelsC->messages.clear();

    // Eventually, one of these nodes wins an election and does some
    // AppendEntries roundtrips to bring the other back in-sync
    DOCTEST_SUBCASE("")
    {
      DOCTEST_INFO("Node A wins");
      rA.periodic(election_timeout);
    }
    else
    {
      DOCTEST_INFO("Node B wins");
      rB.periodic(election_timeout);
    }

    // Election
    dispatch_all(nodes, node_idA);
    dispatch_all(nodes, node_idB);
    dispatch_all(nodes, node_idC);

    dispatch_all(nodes, node_idA);
    dispatch_all(nodes, node_idB);
    dispatch_all(nodes, node_idC);

    // Dispatch all until coherence, bounded by the length of the longest log
    const auto max_iterations = std::max(rA.get_last_idx(), rB.get_last_idx());
    for (size_t i = 0; i < max_iterations; ++i)
    {
      rA.periodic(request_timeout);
      rB.periodic(request_timeout);

      dispatch_all(nodes, node_idA);
      dispatch_all(nodes, node_idB);
      dispatch_all(nodes, node_idC);

      dispatch_all(nodes, node_idA);
      dispatch_all(nodes, node_idB);
      dispatch_all(nodes, node_idC);
    }

    DOCTEST_REQUIRE(rA.get_last_idx() > 3);
    DOCTEST_REQUIRE(rA.get_last_idx() == rB.get_last_idx());
    DOCTEST_REQUIRE(rB.get_last_idx() == rC.get_last_idx());

    DOCTEST_REQUIRE(rA.get_commit_idx() > 3);
    DOCTEST_REQUIRE(rA.get_commit_idx() == rB.get_commit_idx());
    DOCTEST_REQUIRE(rB.get_commit_idx() == rC.get_commit_idx());
  }
}
