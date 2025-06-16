extern crate clap;
extern crate stateright;
use clap::Parser;
mod model;
use model::{ModelCfg, Msg, NextStep, Node, State};
use stateright::{
    actor::*,
    report::WriteReporter,
    util::{HashableHashMap, HashableHashSet},
    Checker, Model,
};
use std::sync::Arc;

fn implies(a: bool, b: bool) -> bool {
    !a || b
}

fn reached_open(model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>) -> bool {
    state
        .actor_states
        .iter()
        .any(|actor_state: &Arc<State>| actor_state.next_step == NextStep::Open)
}

fn unanimous_votes(model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>) -> bool {
    let peers: HashableHashSet<Id> = (0..model.cfg.n_nodes)
        .map(|i| Id::from(i as usize))
        .collect();
    state.actor_states.iter().all(|actor_state: &Arc<State>| {
        actor_state.submitted_vote.is_some()
            && actor_state.submitted_vote.clone().unwrap().1.recv == peers
    })
}

fn liveness_properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = model.property(
        stateright::Expectation::Eventually,
        "Unanimous votes => no deadlock",
        |model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
            // Define deadlock as a path which does not reach open
            // Hence unanimous votes => reach open
            // Hence on every path unanimous votes => <> reached open
            // Since votes are not forgotten on a node, we check for a state where unanimous votes => reached open
            return implies(unanimous_votes(model, state), reached_open(model, state));
        },
    );
    return model;
}

fn invariant_properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = model.property(
        stateright::Expectation::Always,
        "No fork",
        |_model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
            // Check if there is no fork in the state
            let open_node_count = state
                .actor_states
                .iter()
                .filter(|actor_state: &&Arc<State>| actor_state.next_step == NextStep::Open)
                .count();
            open_node_count <= 1
        },
    );
    return model;
}

fn reachable_properties(model: ActorModel<Node, ModelCfg, ()>) -> ActorModel<Node, ModelCfg, ()> {
    let model = model
        .property(
            stateright::Expectation::Sometimes,
            "Open",
            |model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
                reached_open(model, state)
            },
        )
        .property(
            stateright::Expectation::Sometimes,
            "Deadlock",
            |_model: &ActorModel<Node, ModelCfg>, state: &ActorModelState<Node>| {
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
                all_open_join && all_votes_delivered
            },
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
#[command(version, about = "CCF auto-open model", long_about = None)]
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
        .spawn_dfs()
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
