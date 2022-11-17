// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "test_common.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include <doctest/doctest.h>

using AllSigsStore = aft::LoggingStubStoreSig;
using AllSigsAdaptor = aft::Adaptor<AllSigsStore>;

void keep_messages_for_multiple(
  const std::set<ccf::NodeId>& targets,
  aft::ChannelStubProxy::MessageList& messages,
  std::optional<size_t> max_to_keep = std::nullopt)
{
  auto it = messages.begin();
  std::map<ccf::NodeId, size_t> kept;
  while (it != messages.end())
  {
    if (
      std::find(targets.begin(), targets.end(), it->first) == targets.end() ||
      (max_to_keep.has_value() && kept[it->first] >= *max_to_keep))
    {
      it = messages.erase(it);
    }
    else
    {
      ++kept[it++->first];
    }
  }
}

void keep_messages_for(
  const ccf::NodeId& target,
  aft::ChannelStubProxy::MessageList& messages,
  std::optional<size_t> max_to_keep = std::nullopt)
{
  keep_messages_for_multiple({target}, messages, max_to_keep);
}

void keep_first_for(
  const ccf::NodeId& target,
  aft::ChannelStubProxy::MessageList& messages,
  std::optional<size_t> max_to_keep = std::nullopt)
{
  keep_messages_for(target, messages, 1);
}

void keep_earliest_append_entries_for_each_target(
  aft::ChannelStubProxy::MessageList& messages)
{
  std::map<
    ccf::NodeId,
    std::pair<aft::Index, aft::ChannelStubProxy::MessageList::iterator>>
    best;
  for (auto it = messages.begin(); it != messages.end(); ++it)
  {
    const auto& [target, contents] = *it;

    const uint8_t* data = contents.data();
    auto size = contents.size();
    auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
    if (msg_type == aft::raft_append_entries)
    {
      const auto ae = *(aft::AppendEntries*)data;

      const auto best_it = best.find(target);
      if (best_it == best.end() || best_it->second.first > ae.prev_idx)
      {
        best[target] = std::make_pair(ae.prev_idx, it);
      }
    }
  }

  aft::ChannelStubProxy::MessageList best_only;
  for (const auto& [node_id, pair] : best)
  {
    const auto& [idx, it] = pair;
    best_only.push_back(*it);
  }

  messages = std::move(best_only);
}

#define TEST_DECLARE_NODE(N) \
  ccf::NodeId node_id##N(#N); \
  auto store##N = std::make_shared<AllSigsStore>(node_id##N); \
  TRaft r##N( \
    raft_settings, \
    std::make_unique<AllSigsAdaptor>(store##N), \
    std::make_unique<aft::LedgerStubProxy>(node_id##N), \
    std::make_shared<aft::ChannelStubProxy>(), \
    std::make_shared<aft::State>(node_id##N), \
    nullptr, \
    nullptr); \
  r##N.start_ticking(); \
  initial_config[node_id##N] = {}; \
  nodes[node_id##N] = &r##N; \
  auto channels##N = channel_stub_proxy(r##N);

/**
  Summary of the behaviour this test aims to explore (for implementation reasons
  the indices in the actual test don't match those in this comment, but the
  logical relationships are the same):

  - Produce an initial state where A is primary in term 1 of a 5-node network,
    has mixed success replicating its entries. Each node's commit index is
    marked by []. The highest index known on f+1 nodes must be persisted, and
    when enough ACKs are received this becomes the commit index on the primary.
    In this case, that index _is_ known as the commit index on the, which is
    [1.2].
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
    However, if the AppendEntries returns an early-estimate of matching index
    (as a previous implementation did), this AppendEntries may actually cause B
    to roll back further than is safe, losing the committed state.
    C->B: AE [1.2, 1.2)
    B->C: AER NACK 1.1 (B's commit index)
    C->B: AE [1.1, 1.1) (Large entries mean this is only a partial catchup)
    B: Rolls back to 1.1

    B: [1.1]
    C: [1.1] 1.2
    D: [1.1]
    E: [1.1]

  - At this point a committed index (1.2) is no longer present on a majority of
    nodes. While the service may be able to recover without making this loss
    visible to users (while C survives, it will continue to share this index
    with other nodes, and fancy election rules mean it will not report commit
    until it reaches 1.2), it's possible for C to die here and B, D, or E to win
    an election and proceed without this committed suffix,
    forking/overwriting 1.2 with 4.2.
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
    DOCTEST_REQUIRE(rA.get_view() == 1);

    // Dispatch initial AppendEntries
    DOCTEST_REQUIRE(4 == dispatch_all(nodes, node_idA, channelsA->messages));

    // Dispatch initial AppendEntriesResponses
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB, channelsB->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC, channelsC->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idD, channelsD->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idE, channelsE->messages));

    DOCTEST_REQUIRE(rA.is_primary());
    DOCTEST_REQUIRE(rA.get_view() == 1);
  }

  DOCTEST_INFO("Entry at 1.1 is received by all nodes");
  {
    auto entry = make_ledger_entry(1, 1);
    rA.replicate(kv::BatchVector{{1, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 1);
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 0);
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
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 1);
  }

  DOCTEST_INFO(
    "Entries at 1.2, 1.3, and 1.4 are received by a majority, and become "
    "committed");
  {
    auto entry = make_ledger_entry(1, 2);
    rA.replicate(kv::BatchVector{{2, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 2);
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 1);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    entry = make_ledger_entry(1, 3);
    rA.replicate(kv::BatchVector{{3, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 3);
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 1);
    // Size limit was reached, so periodic is not needed
    // rA.periodic(request_timeout);

    entry = make_ledger_entry(1, 4);
    rA.replicate(kv::BatchVector{{4, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 4);
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 1);
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

    // NB: AppendEntriesResponses are not dispatched yet. So 1.4 is present on
    // f+1 nodes and should be persisted, but nobody knows this yet
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
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 4);

    // Nodes B and C have this commit index, and are responsible for persisting
    // it
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_committed_seqno());
    DOCTEST_REQUIRE(rC.get_last_idx() >= rA.get_committed_seqno());
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
    DOCTEST_REQUIRE(rB.get_view() == 2);
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
    DOCTEST_REQUIRE(rB.get_committed_seqno() < rA.get_committed_seqno());
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_committed_seqno());
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
    DOCTEST_REQUIRE(rC.get_view() == 3);

    DOCTEST_REQUIRE(rB.get_last_idx() == 7);
    DOCTEST_REQUIRE(rC.get_last_idx() == 4);

    // The early AppendEntries that C tries to send are lost
    rC.periodic(request_timeout);
    channelsC->messages.clear();

    DOCTEST_REQUIRE(rB.get_last_idx() == 7);

    DOCTEST_REQUIRE(rB.get_committed_seqno() < rA.get_committed_seqno());
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_committed_seqno());
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
      rC.periodic(request_timeout);
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
    DOCTEST_REQUIRE(rB.get_last_idx() >= rA.get_committed_seqno());

    // B's term history must match the current primary's
    DOCTEST_REQUIRE(rB.get_last_idx() <= rC.get_last_idx());
    DOCTEST_REQUIRE(
      rB.get_view_history(rB.get_last_idx()) ==
      rC.get_view_history(rB.get_last_idx()));
  }
}

struct WorstCase
{};
struct RandomCase
{};

// This tests the case where 2 nodes have multiple terms of disagreement. This
// involves a 3-node network, where the 3rd node is purely there to trigger
// elections and allow the other 2 to advance terms, but they never communicate
// with each other and are unable to advance commit. Eventually their connection
// is healed, and one of them efficiently brings the other back in line, without
// losing any committed state.
DOCTEST_TEST_CASE_TEMPLATE("Multi-term divergence", T, WorstCase, RandomCase)
{
  constexpr bool is_worst_case = std::is_same_v<T, WorstCase>;

  logger::config::default_init();
  logger::config::level() = logger::FAIL;

  const auto seed = 1668601152;
  // const auto seed = time(NULL);
  DOCTEST_INFO("Using seed: ", seed);
  srand(seed);

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

  // These are only used in the RandomCase
  std::vector<uint8_t> persisted_entry;
  aft::Index persisted_idx;

  {
    DOCTEST_INFO("Node A is the initial primary");
    rA.periodic(election_timeout);

    // Initial election
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));

    DOCTEST_REQUIRE(rA.is_primary());
    DOCTEST_REQUIRE(rA.get_view() == 1);

    // Election-triggered heartbeats
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));
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
    if (rC.get_view() < primary.get_view())
    {
      primary.periodic(request_timeout);
      keep_messages_for(node_idC, channels_primary->messages);
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, primary_id));
      channelsC->messages.clear();
    }

    DOCTEST_REQUIRE(rC.get_view() >= primary.get_view());

    if (rC.get_view() > primary.get_view())
    {
      // Trigger a message from the intended primary, so C will respond with its
      // current term
      if (primary.is_primary())
      {
        // If we were already primary, then request_timeout will produce an
        // AppendEntries
        primary.periodic(request_timeout);
      }
      else
      {
        // If we weren't, wait election_timeout and send a RequestVote
        primary.periodic(election_timeout);
      }

      // Send just this message, to node C
      keep_messages_for(node_idC, channels_primary->messages);
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, primary_id));

      // Send the NACKy response, containing C's current view
      keep_messages_for(primary_id, channelsC->messages);
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));

      DOCTEST_REQUIRE(rC.get_view() == primary.get_view());
    }
    else
    {
      // Else this was already the primary, in the same term as C. Wait
      // election_timeout to step down
      primary.periodic(election_timeout);
      channels_primary->messages.clear();
    }

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
      auto entry = make_ledger_entry(primary.get_view(), idx);
      primary.replicate(
        kv::BatchVector{{idx, entry, true, hooks}}, primary.get_view());
    }

    // All related AppendEntries are lost
    channels_primary->messages.clear();
  };

  const auto num_terms = rand() % 30 + 5;
  if constexpr (is_worst_case)
  {
    DOCTEST_INFO("Hard-coded worst-case");
    // Worst-case is tiny, perfectly interleaved terms
    for (size_t i = 0; i < num_terms; ++i)
    {
      create_term_on(i % 2 == 0, 1);
    }
  }
  else
  {
    DOCTEST_INFO("Randomized case");
    DOCTEST_INFO(
      "Primary produces some entries that are committed and universally known "
      "to be committed");

    auto entry = make_ledger_entry(1, 1);
    rA.replicate(kv::BatchVector{{1, entry, true, hooks}}, 1);
    entry = make_ledger_entry(1, 2);
    rA.replicate(kv::BatchVector{{2, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(rA.get_last_idx() == 2);
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 0);
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
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 2);

    // After a periodic heartbeat
    rA.periodic(request_timeout);
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idB));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_idC));

    // All nodes know that this is committed
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 2);
    DOCTEST_REQUIRE(rB.get_committed_seqno() == 2);
    DOCTEST_REQUIRE(rC.get_committed_seqno() == 2);

    // Node A produces 2 additional entries that A and B have, and 2 additional
    // entries that are only present on A
    entry = make_ledger_entry(1, 3);
    rA.replicate(kv::BatchVector{{3, entry, true, hooks}}, 1);

    entry = make_ledger_entry(1, 4);
    rA.replicate(kv::BatchVector{{4, entry, true, hooks}}, 1);
    keep_messages_for(node_idB, channelsA->messages);
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_idA));

    entry = make_ledger_entry(1, 5);
    rA.replicate(kv::BatchVector{{5, entry, true, hooks}}, 1);

    entry = make_ledger_entry(1, 6);
    rA.replicate(kv::BatchVector{{6, entry, true, hooks}}, 1);
    channelsA->messages.clear();
    channelsB->messages.clear();

    DOCTEST_REQUIRE(rA.get_last_idx() == 6);
    DOCTEST_REQUIRE(rB.get_last_idx() == 4);
    DOCTEST_REQUIRE(rC.get_last_idx() == 2);

    // Commit did not advance, though 4 is present on f+1 nodes and will be
    // persisted from here
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 2);
    DOCTEST_REQUIRE(rB.get_committed_seqno() == 2);
    DOCTEST_REQUIRE(rC.get_committed_seqno() == 2);

    persisted_idx = 4;
    persisted_entry = rB.ledger->ledger[persisted_idx - 1];

    // For several terms, we randomly choose a primary and have them create an
    // additional suffix term. This produces unique logs on each node, like the
    // following:
    //
    // Index:   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
    // ------------------------------------------------------------------
    // TermA:   1   1   1   1   3   3   3   3   3   6   8   9   9   9   9
    // TermB:   1   1   1   4   4   4   5   5   5   5   7  10  10  10  10
    // TermC:   1   1
    for (size_t i = 0; i < num_terms; ++i)
    {
      // Always produce at least one entry in the new term
      create_term_on(rand() % 2 == 0, rand() % 6 + 1);
    }

    // Ensure at least one term on each
    create_term_on(true, 1);
    create_term_on(false, 1);

    // Nodes A and B now have long, distinct, multi-term non-committed suffixes.
    // Node C has not advanced its log at all
    DOCTEST_REQUIRE(rA.get_committed_seqno() == 2);
    DOCTEST_REQUIRE(rB.get_committed_seqno() == 2);
    DOCTEST_REQUIRE(rC.get_committed_seqno() == 2);

    DOCTEST_REQUIRE(rA.get_last_idx() > 4);
    DOCTEST_REQUIRE(rB.get_last_idx() > 3);
    DOCTEST_REQUIRE(rC.get_last_idx() == 2);

    DOCTEST_REQUIRE(rA.get_view() != rB.get_view());
    DOCTEST_REQUIRE(
      rA.get_view_history(rA.get_last_idx()) !=
      rB.get_view_history(rB.get_last_idx()));
    {
      // Small sanity check - its not as simple as one is a prefix of the other
      const auto common_last_idx =
        std::min(rA.get_last_idx(), rB.get_last_idx());
      const auto history_on_A = rA.get_view_history(common_last_idx);
      const auto history_on_B = rB.get_view_history(common_last_idx);
      DOCTEST_REQUIRE(history_on_A != history_on_B);

      // In fact they diverge almost immediately
      DOCTEST_REQUIRE(history_on_A[1] != history_on_B[1]);
    }
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

    auto dump_node = [](auto& raft_node) {
      const auto last_idx = raft_node.get_last_idx();
      LOG_FAIL_FMT("  last_idx: {}", last_idx);
      std::vector<aft::Index> view_history =
        raft_node.get_view_history(last_idx);
      LOG_FAIL_FMT("  view_history: {}", fmt::join(view_history, ", "));
      std::vector<std::vector<std::string>> tx_ids;
      ccf::View last_view = 0;
      for (auto idx = 1; idx <= raft_node.get_last_idx(); ++idx)
      {
        auto view = raft_node.get_view(idx);
        if (view != last_view)
        {
          tx_ids.push_back({});
          last_view = view;
        }
        tx_ids.back().push_back(fmt::format("{}.{}", view, idx));
      }
      LOG_FAIL_FMT("  Tx IDs:");
      for (const auto& term : tx_ids)
      {
        LOG_FAIL_FMT("    {}", fmt::join(term, ", "));
      }
    };

    LOG_FAIL_FMT(
      "Before bringing everyone up-to-date, here's the ledger on each node");
    LOG_FAIL_FMT("A:");
    dump_node(rA);
    LOG_FAIL_FMT("B:");
    dump_node(rB);
    LOG_FAIL_FMT("C:");
    dump_node(rC);

    auto& rPrimary = rA.is_primary() ? rA : rB;
    const auto id_primary = rA.is_primary() ? node_idA : node_idB;
    auto& channelsPrimary = rA.is_primary() ? channelsA : channelsB;
    {
      DOCTEST_INFO("Catch node C up");
      auto attempts = 0u;

      while (rC.get_last_idx() < rPrimary.get_last_idx())
      {
        // Avoid infinite loop
        DOCTEST_REQUIRE(attempts++ < rPrimary.get_last_idx());
        rPrimary.periodic(request_timeout);
        dispatch_all(nodes, id_primary);
        dispatch_all(nodes, node_idC);
      }

      // One last roundtrip to sync commit index
      rPrimary.periodic(request_timeout);
      dispatch_all(nodes, id_primary);
      dispatch_all(nodes, node_idC);

      channelsPrimary->messages.clear();
    }

    // NB: If we were probing linearly backwards to find the matching index,
    // then we would need O(n) probe+response roundtrips followed by (in the
    // worst case, which we simulate by dropping most AEs) O(n) AEs from that
    // index to get them caught up again.
    // Instead, thanks to smarter backtracking calculations, we should be
    // bounded in the worst case by the number of terms in the primary's log.
    size_t log_length = rPrimary.get_last_idx();
    size_t term_length;
    {
      std::vector<aft::Index> term_history =
        rPrimary.get_view_history(log_length);
      term_length = std::unique(term_history.begin(), term_history.end()) -
        term_history.begin();
    }

    DOCTEST_INFO("Bring other node in-sync");
    const auto id_other = rA.is_primary() ? node_idB : node_idA;

    {
      // Do (up-to) term_length + 1 round-trips, to discover _where_ the
      // histories diverge
      auto discovery_round_trips_completed = 0;
      while (true)
      {
        rPrimary.periodic(request_timeout);
        keep_earliest_append_entries_for_each_target(channelsPrimary->messages);

        // Assert that the advertised indices never step before the persisted
        // index which was present on f+1 nodes.
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
          nodes, id_primary, [&](const auto& ae) {
            DOCTEST_REQUIRE(ae.prev_idx >= persisted_idx);
          });
        bool accepted = false;
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
          nodes, id_other, [&](const auto& aer) {
            DOCTEST_REQUIRE(aer.last_log_idx >= persisted_idx);
            accepted = aer.success == aft::AppendEntriesResponseType::OK;
          });

        ++discovery_round_trips_completed;

        if (accepted)
        {
          LOG_FAIL_FMT(
            "Found agreement point after {} roundtrips",
            discovery_round_trips_completed);
          break;
        }

        DOCTEST_REQUIRE(discovery_round_trips_completed <= term_length);
      }

      if constexpr (is_worst_case)
      {
        // Confirm that the intended worst-case really _is_ the worst-case
        DOCTEST_REQUIRE(discovery_round_trips_completed == term_length + 1);
      }

      std::cout
        << fmt::format(
             "Discovered agreement point after {} round-trips, with {} terms",
             discovery_round_trips_completed,
             term_length)
        << std::endl;
    }

    {
      // Now we need (up-to) log_length * 2 - 1 roundtrips to actually catch up.
      // This can be thought of as log_length - 1 "sync attempts", where each
      // sync attempt only advances the trailing node's log by a single entry.
      // Each sync attempt requires 2 roundtrips, because:
      // - The primary the primary believes it has delivered all, so the backups
      // should be up-to-date
      // - We need a roundtrip (where the primary attempts a heartbeat, which
      // gets a NACK because the follower remains behind), to convince the
      // primary to try again
      // - Then the primary tries sending AEs for _every_ subsequent entry
      // - We simulate a bad connection/bad batching by only delivering the
      // first, so the follower advances by a single entry
      // - Repeat
      auto catchup_sync_attempts_completed = 0;

      // The awkward "- 1" is because the final discovery round-trip already
      // completed is actually the first successful "catch the follower up"
      // message as well - they've ACK'd the first entry and appended it already
      const auto max_catchup_attempts = log_length - 1;

      while (true)
      {
        // Periodic on primary sends heartbeats, keep only the first
        rPrimary.periodic(request_timeout);
        keep_earliest_append_entries_for_each_target(channelsPrimary->messages);

        // Deliver this heartbeat AE, and its NACK response
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
          nodes, id_primary, [&](const auto& ae) {
            DOCTEST_REQUIRE(ae.prev_idx == rPrimary.get_last_idx());
          });
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
          nodes, id_other, [&](const auto& aer) {
            DOCTEST_REQUIRE(
              aer.success == aft::AppendEntriesResponseType::FAIL);
          });

        // Periodic on primary produces AEs, keep on the first
        rPrimary.periodic(request_timeout);
        keep_earliest_append_entries_for_each_target(channelsPrimary->messages);

        // Deliver this AE, and its response. Assert that the advertised indices
        // never step before the persisted index which was present on f+1 nodes.
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
          nodes, id_primary, [&](const auto& ae) {
            DOCTEST_REQUIRE(ae.prev_idx >= persisted_idx);
          });
        dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
          nodes, id_other, [&](const auto& aer) {
            DOCTEST_REQUIRE(aer.last_log_idx >= persisted_idx);
            DOCTEST_REQUIRE(aer.success == aft::AppendEntriesResponseType::OK);
          });

        ++catchup_sync_attempts_completed;

        // Break early if we've already caught up
        if (
          rA.get_last_idx() == rB.get_last_idx() &&
          rA.get_last_idx() == rA.get_committed_seqno() &&
          rA.get_committed_seqno() == rB.get_committed_seqno())
        {
          break;
        }

        DOCTEST_REQUIRE(catchup_sync_attempts_completed < max_catchup_attempts);
      }

      if constexpr (is_worst_case)
      {
        // Confirm that the intended worst-case really _is_ the worst-case
        DOCTEST_REQUIRE(
          catchup_sync_attempts_completed == max_catchup_attempts);
      }

      std::cout << fmt::format(
                     "Brought node in-sync {} attempts, with {} entries in log",
                     catchup_sync_attempts_completed,
                     log_length)
                << std::endl;

      {
        DOCTEST_INFO("The final state is synced on all nodes");

        DOCTEST_REQUIRE(rA.get_last_idx() == rB.get_last_idx());
        DOCTEST_REQUIRE(rB.get_last_idx() == rC.get_last_idx());

        DOCTEST_REQUIRE(rA.get_committed_seqno() == rB.get_committed_seqno());
        DOCTEST_REQUIRE(rB.get_committed_seqno() == rC.get_committed_seqno());

        const auto term_history_on_A = rA.get_view_history(rA.get_last_idx());
        const auto term_history_on_B = rB.get_view_history(rB.get_last_idx());
        const auto term_history_on_C = rC.get_view_history(rC.get_last_idx());
        DOCTEST_REQUIRE(term_history_on_A == term_history_on_B);
        DOCTEST_REQUIRE(term_history_on_B == term_history_on_C);

        const auto ledger_on_A = rA.ledger->ledger;
        const auto ledger_on_B = rB.ledger->ledger;
        const auto ledger_on_C = rC.ledger->ledger;
        DOCTEST_REQUIRE(ledger_on_A == ledger_on_B);
        DOCTEST_REQUIRE(ledger_on_B == ledger_on_C);

        if constexpr (!is_worst_case)
        {
          // In the random case, assert that the pre-constrcted shared prefix is
          // still here
          DOCTEST_REQUIRE(rA.get_last_idx() > 3);
          DOCTEST_REQUIRE(rA.get_committed_seqno() > 3);

          // And finally, that thing we said was persisted earlier (but wasn't
          // known to be committed), is still present on all nodes
          DOCTEST_REQUIRE(ledger_on_A.size() > persisted_idx);
          DOCTEST_REQUIRE(ledger_on_A[persisted_idx - 1] == persisted_entry);
        }
      }
    }
  }
}
