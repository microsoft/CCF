---- MODULE selfhealingopen ----

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
  NID

MAJ_QUORUM_LIMIT == (Cardinality(NID)) \div 2 + 1

VARIABLES 
  next_step,
  txids,
  gossip_msgs,
  recv_gossips,
  vote_msgs,
  open_msgs

vars == <<next_step, txids, gossip_msgs, recv_gossips, vote_msgs, open_msgs>>

TypeOk ==
  /\ next_step \in [NID -> {"gossip", "vote", "open/join", "open", "join"}]
  /\ txids \in [NID -> Nat]
  /\ gossip_msgs \subseteq [
    src : NID,
    txid : Nat
    ]
  /\ recv_gossips \in [NID -> SUBSET gossip_msgs]
  /\ vote_msgs \subseteq [
    src : NID,
    vote : NID,
    recv : SUBSET NID
    ]
  /\ open_msgs \subseteq [
    src : NID
    ]

TXID == 
  CHOOSE F \in [NID -> 1..Cardinality(NID)]:
  \A k1, k2 \in DOMAIN F: F[k1] = F[k2] => k1 = k2

Init ==
    /\ next_step = [n \in NID |-> "gossip"]
    /\ txids = [n \in NID|-> TXID[n]]
    /\ gossip_msgs = {}
    /\ recv_gossips = [n \in NID |-> {}]
    /\ vote_msgs = {}
    /\ open_msgs = {}

ActionSendGossip(n) ==
  LET msg == [src |-> n, txid |-> txids[n]] IN
  /\ next_step[n] = "gossip"
  /\ next_step' = [next_step EXCEPT ![n] = "vote"]
  /\ recv_gossips' = [recv_gossips EXCEPT ![n] = recv_gossips[n] \cup {msg}]
  /\ gossip_msgs' = gossip_msgs \cup {msg}
  /\ UNCHANGED << txids, vote_msgs, open_msgs >>

ActionRecvGossip(n) ==
  \E m \in gossip_msgs:
  /\ m \notin recv_gossips[n]
  /\ recv_gossips' = [recv_gossips EXCEPT ![n] = recv_gossips[n] \cup {m}]
  /\ UNCHANGED << next_step, txids, gossip_msgs, vote_msgs, open_msgs >>

Vote(n) ==
  LET recv_nodes == {g.src : g \in recv_gossips[n]} 
      max_txid_gossip == 
       CHOOSE g \in recv_gossips[n]:
       \A g1 \in recv_gossips[n]: g.txid >= g1.txid
      vote == [src |-> n, vote |-> max_txid_gossip.src, recv |-> recv_nodes]
  IN 
  /\ next_step[n] = "vote"
  /\ next_step' = [next_step EXCEPT ![n] = "open/join"]
  /\ vote_msgs' = vote_msgs \cup {vote}
  /\ UNCHANGED << txids, gossip_msgs, recv_gossips, open_msgs >>

ActionVoteQuorum(n) ==
  \* Non-Unanimous gossips can cause deadlocks
  /\ {g.src : g \in recv_gossips[n]} = NID
  /\ Vote(n)

ActionVoteTimeout(n) ==
  /\ Cardinality({g.src : g \in recv_gossips[n]}) >= MAJ_QUORUM_LIMIT
  /\ Vote(n)

ActionOpen(n) ==
  \E Vs \in SUBSET {v \in vote_msgs: v.vote = n}:
  /\ Cardinality(Vs) >= MAJ_QUORUM_LIMIT
  /\ next_step[n] = "open/join"
  /\ next_step' = [next_step EXCEPT ![n] = "open"]
  /\ open_msgs' = open_msgs \cup {[src |-> n]}
  /\ UNCHANGED << txids, gossip_msgs, recv_gossips, vote_msgs >>

ActionJoin(n) ==
  \E o \in open_msgs:
  /\ next_step[n] = "open/join"
  /\ next_step' = [next_step EXCEPT ![n] = "join"]
  /\ UNCHANGED << txids, gossip_msgs, recv_gossips, vote_msgs, open_msgs >>


Next ==
    \E n \in NID:
    \/ ActionSendGossip(n)
    \/ ActionRecvGossip(n)
    \/ ActionVoteQuorum(n)
    \/ ActionVoteTimeout(n)
    \/ ActionOpen(n)
    \/ ActionJoin(n)

Spec == Init /\ [][Next]_vars

InvNoFork == 
  (Cardinality({n \in NID: next_step[n] = "open"}) <= 1)

InvCorrectState == ~\A n \in NID: next_step[n] \in {"open", "join"}

\* We optimally should be unable to reach a deadlock state
\* where every node is blocked but it may be impossible due to timeouts
InvNoDeadlockStates == 
    (\A n \in NID: next_step[n] = "open/join")
    =>
    (
        \E n \in NID:
        \/ ENABLED ActionOpen(n)
        \/ ENABLED ActionJoin(n)
    )

InvUnanimousLiveVotesNoDeadlock ==
  LET live_nid == {n \in NID: next_step[n] /= "gossip"} IN
  (\A m \in vote_msgs: m.recv = live_nid) => InvNoDeadlockStates

InvNonUnanimousOpen == 
LET live_nid == {n \in NID: next_step[n] /= "gossip"} IN
  ~ /\ \E n \in NID: next_step[n] = "gossip"
    /\ \E n \in NID: next_step[n] = "open"
    /\ \A m \in vote_msgs: m.recv = live_nid
    /\ \A n \in NID: next_step[n] \in {"gossip", "open", "join"}

Symmetry == Permutations(NID)

====