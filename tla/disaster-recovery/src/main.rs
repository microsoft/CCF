extern crate clap;
extern crate stateright;
use clap::Parser;
mod model;
use model::{ModelCfg, Msg, NextStep, Node, State};
use stateright::{actor::*, report::WriteReporter, util::HashableHashSet, Checker, Model};
use std::sync::Arc;

fn implies(a: bool, b: bool) -> bool {
    !a || b
}

fn reached_open(state: &ActorModelState<Node>) -> bool {
    state
        .actor_states
        .iter()
        .any(|actor_state: &Arc<State>| matches!(actor_state.next_step, NextStep::Open { .. }))
}

fn reached_open_timeout(state: &ActorModelState<Node>, expected_to_timeout: bool) -> bool {
    state.actor_states.iter().any(|actor_state: &Arc<State>| {
        matches! (
            actor_state.next_step,
            NextStep::Open {timeout} if timeout == expected_to_timeout
        )
    })
}

fn unanimous_votes(model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>) -> bool {
    let peers: HashableHashSet<Id> = (0..model.cfg.n_nodes)
        .map(|i| Id::from(i as usize))
        .collect();
    state.actor_states.iter().all(|actor_state: &Arc<State>| {
        actor_state.submitted_vote.is_some()
            && peers.iter().all(|peer| {
                actor_state
                    .submitted_vote
                    .clone()
                    .unwrap()
                    .1
                    .recv
                    .iter()
                    .any(|g| g.src == *peer)
            })
    })
}

fn majority_have_same_maximum(state: &ActorModelState<Node>) -> bool {
    // get the chosen replica of each replica into a vector and sort that vector
    // that there is only one value up to the n/2th index
    let mut chosen_replicas: Vec<Id> = state
        .actor_states
        .iter()
        .filter(|actor_state: &&Arc<State>| actor_state.submitted_vote.is_some())
        .map(|actor_state| {
            actor_state
                .submitted_vote
                .clone()
                .unwrap()
                .1
                .recv
                .iter()
                .max_by_key(|g| (g.txid, g.src))
                .unwrap()
                .src
        })
        .collect();
    chosen_replicas.sort();
    let majority_idx = state.actor_states.len() / 2;
    let majority_chosen_replica = chosen_replicas.get(majority_idx);
    majority_chosen_replica.is_some()
        && chosen_replicas[0..majority_idx]
            .iter()
            .all(|&r| r == *majority_chosen_replica.unwrap())
}

fn liveness_properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = model
        .property(
            stateright::Expectation::Eventually,
            "Unanimous votes => no chance of a fork",
            |model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
                // Define deadlock as a path which does not reach open without
                // Hence unanimous votes => reach open
                // Hence on every path unanimous votes => <> reached open
                // Since votes are not forgotten on a node, we check for a state where unanimous votes => reached open
                return implies(
                    unanimous_votes(model, state),
                    reached_open_timeout(state, false),
                );
            },
        )
        .property(
            stateright::Expectation::Eventually,
            "Open",
            |_, state: &ActorModelState<Node>| {
                // all runs should eventually open, either via the reliable method, or via the failover timeout
                reached_open(state)
            },
        )
        .property(
            stateright::Expectation::Eventually,
            "Majority votes => no fork",
            |_, state: &ActorModelState<Node>| {
                return implies(
                    majority_have_same_maximum(state),
                    reached_open_timeout(state, false),
                );
            },
        );
    return model;
}

fn invariant_properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = model
        .property(
            stateright::Expectation::Always,
            "No open with timeout, no fork",
            |_model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
                // Check if there is no fork in the state
                let open_node_count = state
                    .actor_states
                    .iter()
                    .filter(|actor_state: &&Arc<State>| {
                        matches!(actor_state.next_step, NextStep::Open { .. })
                    })
                    .count();
                implies(!reached_open_timeout(state, true), open_node_count <= 1)
            },
        )
        .property(
            stateright::Expectation::Always,
            "Deadlock",
            |_model, state| {
                let all_open_join = state
                    .actor_states
                    .iter()
                    .all(|actor_state: &Arc<State>| actor_state.next_step == NextStep::OpenJoin);
                let all_votes_delivered = state
                    .network
                    .iter_all()
                    .filter(|msg| matches!(msg.msg, Msg::Vote(_)))
                    .count()
                    == 0;
                !(all_open_join && all_votes_delivered)
            },
        )
        .property(
            stateright::Expectation::Always,
            "Persist committed txs",
            |_model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
                let majority_idx = state.actor_states.len() / 2;
                let commit_txid = state
                    .actor_states
                    .iter()
                    .map(|actor_state| actor_state.txid)
                    .collect::<Vec<_>>()[majority_idx];
                let cond = state
                    .actor_states
                    .iter()
                    .filter(|actor_state: &&Arc<State>| {
                        matches!(actor_state.next_step, NextStep::Open { .. })
                    })
                    .all(|actor_state: &Arc<State>| actor_state.txid >= commit_txid);
                implies(!reached_open_timeout(state, true), cond)
            },
        );
    return model;
}

fn reachable_properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = model
        .property(
            stateright::Expectation::Sometimes,
            "Open is possible",
            |_, state| implies(state.actor_states.len() > 1, reached_open(state)),
        )
        .property(
            stateright::Expectation::Sometimes,
            "Unsafe open with timeout",
            |_, state| reached_open_timeout(state, true),
        )
        .property(
            stateright::Expectation::Sometimes,
            "Majority vote still opens without timeout",
            |_model, state| majority_have_same_maximum(state) && reached_open_timeout(state, false),
        );
    return model;
}

fn properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = liveness_properties(model);
    let model = invariant_properties(model);
    let model = reachable_properties(model);
    return model;
}

#[derive(Parser, Debug)]
#[command(version, about = "Model for CCF's self-healing-open", long_about = None)]
struct CliArgs {
    #[clap(short, long, default_value = "3")]
    n_nodes: usize,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Check the model
    Check,
    /// Serve the model on localhost:8080
    Serve,
}

fn check(model: ActorModel<Node, ModelCfg, ()>) {
    let checker = model
        .checker()
        .spawn_bfs()
        .join_and_report(&mut WriteReporter::new(&mut std::io::stderr()));
    checker.assert_properties();
}

fn serve(model: ActorModel<Node, ModelCfg, ()>) {
    let checker = model.checker();
    println!("Serving model on http://localhost:8080");
    checker.serve("localhost:8080");
}

fn main() {
    let args = CliArgs::parse();

    let model = ModelCfg {
        n_nodes: args.n_nodes,
    }
    .into_model();

    let model = properties(model);

    match args.command {
        Commands::Check => check(model),
        Commands::Serve => serve(model),
    }
}
