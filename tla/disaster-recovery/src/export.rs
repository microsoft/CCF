//! Dependency-free canonical export of the reachable state graph.
//!
//! Implements the shared `ccf-legacy-dr-graph-v1` TSV contract: the model is
//! enumerated exhaustively using only the public `stateright::Model`
//! interface (`init_states`, `next_steps`, `within_boundary`), and every
//! state/action is serialized with an explicit hand-written grammar (never
//! `Debug`), so the output is stable across compiler/library versions and
//! diffable byte-for-byte against an independent re-implementation (e.g.
//! Python, Lean) of the same state machine.
//!
//! No new dependencies are introduced: only `stateright` (already a direct
//! dependency) and `std` are used.
//!
//! # Format
//!
//! ```text
//! format\tccf-legacy-dr-graph-v1
//! nodes\t<N>
//! init\t<ID>
//! state\t<ID>\t<STATE_KEY>\t<BITSTRING>   (one per reachable state)
//! edge\t<SRC_ID>\t<ACTION>\t<DST_ID>      (one per reachable transition)
//! ```
//!
//! `<ID>` is a canonical, dense integer id (`0..N_STATES`) assigned by
//! sorting every reachable state's `<STATE_KEY>` (see below) lexicographically
//! and numbering them in that order -- *not* BFS/discovery order -- so ids are
//! reproducible independent of traversal strategy. `state` records are
//! emitted in ascending `<ID>` order (equivalently, ascending `<STATE_KEY>`
//! order). `edge` records are emitted sorted by the tuple
//! `(<SRC_ID>, <ACTION> text, <DST_ID>)` (numeric on the ids, lexicographic on
//! the action text), and de-duplicated. Repeating the full `<STATE_KEY>` in
//! every edge does not scale (e.g. `n=3` already has 105,558 states / 552,282
//! edges), so edges reference states only by `<ID>`; a reader reconstructs the
//! `<STATE_KEY>` for any `<ID>` via the `state` block.
//!
//! `<BITSTRING>` is exactly 9 characters of `1`/`0`, one per predicate
//! currently registered on the model via `ActorModel::property`
//! (`model.properties`), in registration order (liveness, then invariant,
//! then reachable properties -- *not* alphabetical). Each bit is the exact
//! existing `Property::condition` closure evaluated on that state, so the
//! export can never drift from `check`/`serve` behaviour, and preserves each
//! predicate's existing (sometimes misleadingly worded) name/meaning even
//! though names themselves are not repeated in the TSV output.
//!
//! Grammar for `<STATE>`/`<ACTION>` tokens (no token contains whitespace):
//!
//! - gossip: `g(src,txid)`
//! - vote: `v(src,[GOSSIPS])` where `GOSSIPS` is a comma-separated gossip list
//! - msg: a gossip, a vote, or `o(id)` (`IAmOpen`)
//! - envelope: `e(src,dst,msg)`
//! - submitted vote: `none` or `some(dst,vote)`
//! - actor: `s(PHASE,[GOSSIPS],[VOTES],SUBMITTED,txid)` where `PHASE` is one
//!   of `vote`, `openjoin`, `open0` (`Open { timeout: false }`), `open1`
//!   (`Open { timeout: true }`), `join`
//! - global state: `S([ACTORS],[TIMERS],[ENVELOPES])` where `ACTORS` is
//!   semicolon-separated (positional, by actor index), `TIMERS` is a
//!   comma-separated list of actor ids with an active election timeout, and
//!   `ENVELOPES` is a comma-separated list of `envelope#count` (count being
//!   the in-flight multiplicity of that exact envelope)
//! - action: `deliver(src,dst,msg)` or `timeout(id,election)`
//!
//! `history` (`H = ()`), `random_choices` (`Node::Random = ()`),
//! `actor_storages` (`Node::Storage = ()`), and `crashed` (always all-`false`,
//! since `max_crashes` is never configured above `0`) are all omitted from
//! `S(...)`: for this model they are always constant/empty and carry no
//! information.
//!
//! Set elements (`GOSSIPS`, `VOTES`) are ordered using the actual Rust
//! `#[derive(Ord)]` implementation of `GossipStruct`/`VoteStruct` (not a
//! string sort), and `ENVELOPES` are ordered using `Envelope<Msg>`'s derived
//! `Ord`. Per `Model::next_state`'s documented contract ("`None` indicates
//! the action does not change state"), only actions for which `next_state`
//! returns `Some` produce an edge; this is preserved by using
//! `Model::next_steps`, whose default implementation already filters out
//! `None` results.

use crate::model::{GossipStruct, ModelCfg, Msg, NextStep, Node, State, Timer, VoteStruct};
use stateright::actor::{
    ActorModel, ActorModelAction, ActorModelState, Envelope, Id, Network, Timers,
};
use stateright::Model;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};

fn fmt_id(id: Id) -> String {
    usize::from(id).to_string()
}

fn fmt_gossip(g: &GossipStruct) -> String {
    format!("g({},{})", fmt_id(g.src), g.txid)
}

/// Clones and sorts a gossip set using `GossipStruct`'s derived `Ord`
/// (compares `src` then `txid`), per the shared contract's "sort set
/// elements by Rust derived Ord".
fn sorted_gossips(set: &stateright::util::HashableHashSet<GossipStruct>) -> Vec<GossipStruct> {
    let mut v: Vec<GossipStruct> = set.iter().cloned().collect();
    v.sort();
    v
}

fn fmt_gossip_list(set: &stateright::util::HashableHashSet<GossipStruct>) -> String {
    let items: Vec<String> = sorted_gossips(set).iter().map(fmt_gossip).collect();
    format!("[{}]", items.join(","))
}

fn fmt_vote(v: &VoteStruct) -> String {
    format!("v({},{})", fmt_id(v.src), fmt_gossip_list(&v.recv))
}

/// Clones and sorts a vote set using `VoteStruct`'s derived `Ord` (compares
/// `src` then `recv`).
fn sorted_votes(set: &stateright::util::HashableHashSet<VoteStruct>) -> Vec<VoteStruct> {
    let mut v: Vec<VoteStruct> = set.iter().cloned().collect();
    v.sort();
    v
}

fn fmt_vote_list(set: &stateright::util::HashableHashSet<VoteStruct>) -> String {
    let items: Vec<String> = sorted_votes(set).iter().map(fmt_vote).collect();
    format!("[{}]", items.join(","))
}

fn fmt_submitted(sv: &Option<(Id, VoteStruct)>) -> String {
    match sv {
        None => "none".to_string(),
        Some((dst, vote)) => format!("some({},{})", fmt_id(*dst), fmt_vote(vote)),
    }
}

fn fmt_phase(n: &NextStep) -> &'static str {
    match n {
        NextStep::Vote => "vote",
        NextStep::OpenJoin => "openjoin",
        NextStep::Open { timeout: false } => "open0",
        NextStep::Open { timeout: true } => "open1",
        NextStep::Join => "join",
    }
}

fn fmt_actor(s: &State) -> String {
    format!(
        "s({},{},{},{},{})",
        fmt_phase(&s.next_step),
        fmt_gossip_list(&s.gossips),
        fmt_vote_list(&s.votes),
        fmt_submitted(&s.submitted_vote),
        s.txid,
    )
}

fn fmt_msg(m: &Msg) -> String {
    match m {
        Msg::Gossip(g) => fmt_gossip(g),
        Msg::Vote(v) => fmt_vote(v),
        Msg::IAmOpen(id) => format!("o({})", fmt_id(*id)),
    }
}

fn fmt_envelope(env: &Envelope<Msg>) -> String {
    format!(
        "e({},{},{})",
        fmt_id(env.src),
        fmt_id(env.dst),
        fmt_msg(&env.msg)
    )
}

/// Tallies in-flight multiplicity per distinct envelope. `Network::iter_all`
/// yields one item per unit of multiplicity regardless of the underlying
/// `Network` variant (this model only ever uses
/// `new_unordered_nonduplicating`, whose internal representation already
/// tracks a count directly), so tallying via `iter_all` is variant-agnostic
/// and stays correct if the network configuration ever changes.
fn network_counts(network: &Network<Msg>) -> Vec<(Envelope<Msg>, usize)> {
    let mut counts: HashMap<Envelope<Msg>, usize> = HashMap::new();
    for env in network.iter_all() {
        *counts.entry(env.to_cloned_msg()).or_insert(0) += 1;
    }
    let mut v: Vec<(Envelope<Msg>, usize)> = counts.into_iter().collect();
    // Envelope<Msg>'s derived Ord (src, dst, msg), per the shared contract.
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

fn fmt_network(network: &Network<Msg>) -> String {
    let items: Vec<String> = network_counts(network)
        .iter()
        .map(|(env, count)| format!("{}#{}", fmt_envelope(env), count))
        .collect();
    format!("[{}]", items.join(","))
}

/// Comma-separated, ascending list of actor ids with an active election
/// timeout. `Timer` currently has a single variant, so presence alone is
/// significant (no timer-kind tag is emitted).
fn fmt_timers(timers_set: &[Timers<Timer>]) -> String {
    let mut ids: Vec<usize> = timers_set
        .iter()
        .enumerate()
        .filter(|(_, t)| t.iter().next().is_some())
        .map(|(i, _)| i)
        .collect();
    ids.sort_unstable();
    let items: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
    format!("[{}]", items.join(","))
}

/// Canonical `S(...)` encoding of a full `ActorModelState<Node>`. Used both
/// as the state field in `state` records and as the basis of the canonical
/// state id, so two independent implementations that compute the same
/// reachable state always produce the same key, regardless of traversal order.
pub fn fmt_state(state: &ActorModelState<Node>) -> String {
    let actors: Vec<String> = state.actor_states.iter().map(|s| fmt_actor(s)).collect();
    format!(
        "S([{}],{},{})",
        actors.join(";"),
        fmt_timers(&state.timers_set),
        fmt_network(&state.network),
    )
}

/// Canonical encoding of an `ActorModelAction`. Only `Deliver` and `Timeout`
/// are part of the `ccf-legacy-dr-graph-v1` contract: this model never
/// produces `Drop` (`LossyNetwork::No`), `Crash`/`Recover` (`max_crashes ==
/// 0`), or `SelectRandom` (no `Actor` ever issues a `ChooseRandom` command),
/// so encountering one is a bug (e.g. a future model config change) rather
/// than a case the contract needs to define.
pub fn fmt_action(action: &ActorModelAction<Msg, Timer, ()>) -> String {
    match action {
        ActorModelAction::Deliver { src, dst, msg } => {
            format!(
                "deliver({},{},{})",
                fmt_id(*src),
                fmt_id(*dst),
                fmt_msg(msg)
            )
        }
        ActorModelAction::Timeout(id, Timer::ElectionTimeout) => {
            format!("timeout({},election)", fmt_id(*id))
        }
        other => unreachable!(
            "action variant {:?} is outside the ccf-legacy-dr-graph-v1 contract \
             (only Deliver/Timeout are ever produced by this model's configuration)",
            other
        ),
    }
}

/// The 9-character `1`/`0` bitstring for `state`, one bit per predicate
/// currently registered on `model` (`model.properties`) in registration
/// order -- i.e. exactly the same `fn` pointers used by `check`/`serve`, so
/// this can never drift from their semantics.
fn predicate_bitstring(
    model: &ActorModel<Node, ModelCfg, ()>,
    state: &ActorModelState<Node>,
) -> String {
    model
        .properties
        .iter()
        .map(|p| {
            if (p.condition)(model, state) {
                '1'
            } else {
                '0'
            }
        })
        .collect()
}

/// Exhaustively enumerates the reachable state graph of `model` via the
/// public `stateright::Model` interface (`init_states`, `next_steps`,
/// `within_boundary`) and writes it to `out` as `ccf-legacy-dr-graph-v1`.
///
/// States are discovered by BFS (for traversal only), but `<ID>`s are
/// assigned afterwards by sorting all discovered `<STATE_KEY>`s
/// lexicographically -- so the numbering is a pure function of the reachable
/// state set, independent of traversal order. Edges reference states by
/// `<ID>` only, keeping output size linear in (states + edges) rather than
/// (edges * average state size).
pub fn export_graph<W: Write>(
    model: &ActorModel<Node, ModelCfg, ()>,
    out: &mut W,
) -> io::Result<()> {
    // Indexed by BFS discovery order (a "discovery id"); remapped to the
    // canonical sorted-key id only once the full state set is known.
    let mut visited: HashMap<ActorModelState<Node>, usize> = HashMap::new();
    let mut keys: Vec<String> = Vec::new();
    let mut bits: Vec<String> = Vec::new();
    let mut frontier: VecDeque<ActorModelState<Node>> = VecDeque::new();
    // (discovery src id, action text, discovery dst id)
    let mut edges: Vec<(usize, String, usize)> = Vec::new();

    let mut init_states = model.init_states();
    assert_eq!(
        init_states.len(),
        1,
        "ccf-legacy-dr-graph-v1 assumes a single deterministic init state"
    );
    let init_state = init_states.remove(0);
    assert!(
        model.within_boundary(&init_state),
        "ccf-legacy-dr-graph-v1 assumes the init state is within the model boundary"
    );
    let init_discovery_id = keys.len();
    keys.push(fmt_state(&init_state));
    bits.push(predicate_bitstring(model, &init_state));
    visited.insert(init_state.clone(), init_discovery_id);
    frontier.push_back(init_state);

    while let Some(s) = frontier.pop_front() {
        let src_discovery_id = *visited
            .get(&s)
            .expect("every frontier state was inserted into `visited` before being queued");
        // `next_steps` (default `Model` trait method) already filters out
        // actions for which `next_state` returns `None`, preserving the
        // documented no-op-suppression contract.
        for (action, ns) in model.next_steps(&s) {
            if !model.within_boundary(&ns) {
                continue;
            }
            let action_key = fmt_action(&action);
            let dst_discovery_id = if let Some(&id) = visited.get(&ns) {
                id
            } else {
                let id = keys.len();
                keys.push(fmt_state(&ns));
                bits.push(predicate_bitstring(model, &ns));
                visited.insert(ns.clone(), id);
                frontier.push_back(ns);
                id
            };
            edges.push((src_discovery_id, action_key, dst_discovery_id));
        }
    }

    // Canonical id assignment: number every discovered state by the
    // lexicographic order of its `<STATE_KEY>`, not by discovery order.
    let mut order: Vec<usize> = (0..keys.len()).collect();
    order.sort_by(|&a, &b| keys[a].cmp(&keys[b]));
    let mut canonical_id: Vec<usize> = vec![0; keys.len()];
    for (id, &discovery_id) in order.iter().enumerate() {
        canonical_id[discovery_id] = id;
    }

    // Remap edges to canonical ids, then sort by (SRC_ID, ACTION, DST_ID) --
    // numeric on the ids (real `usize` comparison, not string comparison),
    // lexicographic on the action text -- and de-duplicate.
    let mut canonical_edges: Vec<(usize, String, usize)> = edges
        .into_iter()
        .map(|(src, action, dst)| (canonical_id[src], action, canonical_id[dst]))
        .collect();
    canonical_edges.sort();
    canonical_edges.dedup();

    writeln!(out, "format\tccf-legacy-dr-graph-v1")?;
    writeln!(out, "nodes\t{}", model.actors.len())?;
    writeln!(out, "init\t{}", canonical_id[init_discovery_id])?;
    for (id, &discovery_id) in order.iter().enumerate() {
        writeln!(
            out,
            "state\t{}\t{}\t{}",
            id, keys[discovery_id], bits[discovery_id]
        )?;
    }
    for (src, action, dst) in &canonical_edges {
        writeln!(out, "edge\t{src}\t{action}\t{dst}")?;
    }
    Ok(())
}
