---- MODULE autoopen ----

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
  NID

MAJ_QUORUM_LIMIT == (Cardinality(NID) + 1) \div 2

VARIABLES 
  next_step,
  txids,
  gossip_msgs,
  vote_msgs,
  open_msgs

vars == <<next_step, txids, gossip_msgs, vote_msgs, open_msgs>>

TypeOk ==
  /\ next_step \in [NID -> {"gossip", "vote", "open/join", "open", "join"}]
  /\ txids \in [NID -> Nat]
  /\ gossip_msgs \subseteq [
    src : NID,
    txid : Nat
    ]
  /\ vote_msgs \subseteq [
    src : NID,
    vote : NID,
    kind : {"quorum", "timeout"}
    ]
  /\ open_msgs \subseteq [
    src : NID
    ]

Init ==
    /\ next_step = [n \in NID |-> "gossip"]
    /\ txids = [n \in NID |-> n]
    /\ gossip_msgs = {}
    /\ vote_msgs = {}
    /\ open_msgs = {}

ActionSendGossip(n) ==
  /\ next_step[n] = "gossip"
  /\ next_step' = [next_step EXCEPT ![n] = "vote"]
  /\ gossip_msgs' = gossip_msgs \cup {[src |-> n, txid |-> txids[n]]}
  /\ UNCHANGED << txids, vote_msgs, open_msgs >>

Vote(n, gossips, kind) ==
  LET max_txid_gossip == 
       CHOOSE g \in gossips:
       \A g1 \in gossips: g.txid >= g1.txid
      vote == [src |-> n, vote |-> max_txid_gossip.src, kind |-> kind]
  IN 
  /\ next_step[n] = "vote"
  /\ next_step' = [next_step EXCEPT ![n] = "open/join"]
  /\ vote_msgs' = vote_msgs \cup {vote}
  /\ UNCHANGED << txids, gossip_msgs, open_msgs >>

ActionVoteQuorum(n) ==
  \E gossips \in SUBSET gossip_msgs:
  \* Non-Unanimous gossips can cause deadlocks
  /\ {g.src : g \in gossips} = NID
  /\ Vote(n, gossips \cup {[src |-> n, txid |-> txids[n]]}, "quorum")

ActionVoteTimeout(n) ==
  \E gossips \in SUBSET gossip_msgs:
  /\ Cardinality({g.src : g \in gossips}) >= MAJ_QUORUM_LIMIT
  /\ Vote(n, gossips \cup {[src |-> n, txid |-> txids[n]]}, "timeout")

ActionOpen(n) ==
  \E Vs \in SUBSET {v \in vote_msgs: v.vote = n}:
  /\ Cardinality(Vs) >= MAJ_QUORUM_LIMIT
  /\ next_step[n] = "open/join"
  /\ next_step' = [next_step EXCEPT ![n] = "open"]
  /\ open_msgs' = open_msgs \cup {[src |-> n]}
  /\ UNCHANGED << txids, gossip_msgs, vote_msgs >>

ActionJoin(n) ==
  \E o \in open_msgs:
  /\ next_step[n] = "open/join"
  /\ next_step' = [next_step EXCEPT ![n] = "join"]
  /\ UNCHANGED << txids, gossip_msgs, vote_msgs, open_msgs >>


Next ==
    \E n \in NID:
    \/ ActionSendGossip(n)
    \/ ActionVoteQuorum(n)
    \/ ActionVoteTimeout(n)
    \/ ActionOpen(n)
    \/ ActionJoin(n)

Spec == Init /\ [][Next]_vars

InvNoTimeoutNoFork == 
  (\A m \in vote_msgs: m.kind = "quorum")
  => 
  (Cardinality({n \in NID: next_step[n] = "open"}) <= 1)

InvCorrectState == ~\A n \in NID: next_step[n] \in {"open", "join"}

\* We optimally should be unable to reach a deadlock state
\* where every node is blocked but it may be impossible with timeouts
InvNoDeadlockStates == 
    (\A n \in NID: next_step[n] = "open/join")
    =>
    (
        \E n \in NID:
        \/ ENABLED ActionOpen(n)
        \/ ENABLED ActionJoin(n)
    )

InvNoTimeoutNoDeadlock ==
  (\A m \in vote_msgs: m.kind = "quorum")
  => InvNoDeadlockStates

====