extern crate stateright;
use stateright::{actor::*, util::HashableHashSet, Rewrite, RewritePlan};
use std::borrow::Cow;

type Txid = u64;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gossip {
    pub src: Id,
    pub txid: Txid,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub src: Id,
    pub recv: HashableHashSet<Id>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Msg {
    Gossip(Gossip),
    Vote(Vote),
    Open,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Timer {
    ElectionTimeout,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum NextStep {
    //    Gossip,
    Vote,
    OpenJoin,
    Open,
    Join,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct State {
    pub next_step: NextStep,
    pub gossips: HashableHashSet<Gossip>,
    pub votes: HashableHashSet<Vote>,
    pub submitted_vote: Option<(Id, Vote)>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Node {
    pub txid: Txid,
    pub peers: HashableHashSet<Id>,
}

impl Node {
    fn vote_for_max<'a, I>(gossips: &I, id: Id) -> (Id, Vote)
    where
        I: Iterator<Item = &'a Gossip> + Clone,
    {
        let dst = gossips
            .clone()
            .max_by(|a, b| a.txid.cmp(&b.txid))
            .unwrap()
            .src;
        let vote = Vote {
            src: id,
            recv: gossips.clone().map(|g| g.src.clone()).collect(),
        };
        return (dst, vote);
    }

    fn other_peers(&self, id: Id) -> Vec<Id> {
        self.peers.iter().filter(|&&p| p != id).cloned().collect()
    }

    fn advance_step(&self, state: &mut State, o: &mut Out<Self>, id: Id, timeout: bool) {
        match state.next_step {
            NextStep::Vote if state.gossips.len() == self.peers.len() || timeout => {
                let (dst, vote) = Node::vote_for_max(&state.gossips.iter(), id);
                state.submitted_vote = Some((dst, vote.clone()));
                o.send(dst, Msg::Vote(vote));
                state.next_step = NextStep::OpenJoin;
            }
            NextStep::OpenJoin if state.votes.len() >= (self.peers.len() + 1) / 2 => {
                state.next_step = NextStep::Open;
                o.broadcast(&self.other_peers(id), &Msg::Open);
            }
            _ => {}
        }
    }
}

impl Actor for Node {
    type Msg = Msg;
    type State = State;
    type Timer = Timer;

    fn on_start(&self, id: Id, o: &mut Out<Self>) -> Self::State {
        let mut gossips = HashableHashSet::new();
        gossips.insert(Gossip {
            src: id,
            txid: self.txid,
        });
        let state = State {
            next_step: NextStep::Vote,
            gossips: gossips,
            votes: HashableHashSet::new(),
            submitted_vote: None,
        };
        o.broadcast(
            &self.other_peers(id),
            &Msg::Gossip(Gossip {
                src: id,
                txid: self.txid,
            }),
        );
        o.set_timer(Timer::ElectionTimeout, model_timeout());
        return state;
    }

    fn on_timeout(&self, id: Id, state: &mut Cow<Self::State>, timer: &Timer, o: &mut Out<Self>) {
        match timer {
            Timer::ElectionTimeout => {
                if state.next_step == NextStep::Vote && !state.gossips.is_empty() {
                    let state = state.to_mut();
                    self.advance_step(state, o, id, true);
                } else {
                  o.set_timer(Timer::ElectionTimeout, model_timeout());
                }
            }
        }
    }

    fn on_msg(
        &self,
        id: Id,
        state: &mut Cow<Self::State>,
        _src: Id,
        msg: Self::Msg,
        o: &mut Out<Self>,
    ) {
        let state = state.to_mut();
        match msg {
            Msg::Gossip(gossip) => {
                // Freeze gossip collection after voting is submitted
                if !state.gossips.contains(&gossip) && state.submitted_vote.is_none() {
                    state.gossips.insert(gossip.clone());
                }
            }
            Msg::Vote(vote) => {
                if !state.votes.contains(&vote) {
                    state.votes.insert(vote);
                }
            }
            Msg::Open => {
                state.next_step = NextStep::Join;
            }
        };
        self.advance_step(state, o, id, false);
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ModelCfg {
    pub n_nodes: usize,
}

impl ModelCfg {
    pub fn into_model(self) -> ActorModel<Node, Self> {
        let peers: HashableHashSet<Id> = (0..self.n_nodes).map(|i| Id::from(i as usize)).collect();
        ActorModel::new(self.clone(), ())
            .actors(
                (0..self.n_nodes)
                    .map(|i| Node {
                        peers: peers.clone(),
                        txid: i as u64,
                    })
                    .collect::<Vec<_>>(),
            )
            //.init_network(Network::new_ordered([]))
            .init_network(Network::new_unordered_nonduplicating([]))
            .lossy_network(LossyNetwork::No)
    }
}

impl Rewrite<Id> for Gossip {
    fn rewrite<S>(&self, plan: &RewritePlan<Id, S>) -> Self {
        Gossip {
            src: self.src.rewrite(plan),
            txid: self.txid,
        }
    }
}

impl Rewrite<Id> for Vote {
    fn rewrite<S>(&self, plan: &RewritePlan<Id, S>) -> Self {
        Vote {
            src: self.src.rewrite(plan),
            recv: self.recv.iter().map(|r| r.rewrite(plan)).collect(),
        }
    }
}

impl Rewrite<Id> for Msg {
    fn rewrite<S>(&self, plan: &RewritePlan<Id, S>) -> Self {
        match self {
            Msg::Gossip(gossip) => Msg::Gossip(gossip.rewrite(plan)),
            Msg::Vote(vote) => Msg::Vote(vote.rewrite(plan)),
            Msg::Open => Msg::Open,
        }
    }
}

impl Rewrite<Id> for Node {
    fn rewrite<S>(&self, plan: &RewritePlan<Id, S>) -> Self {
        Node {
            txid: self.txid,
            peers: self.peers.iter().map(|p| p.rewrite(plan)).collect(),
        }
    }
}

impl Rewrite<Id> for State {
    fn rewrite<S>(&self, plan: &RewritePlan<Id, S>) -> Self {
        State {
            next_step: self.next_step.clone(),
            gossips: self.gossips.iter().map(|g| g.rewrite(plan)).collect(),
            votes: self.votes.iter().map(|v| v.rewrite(plan)).collect(),
            submitted_vote: None,
        }
    }
}

impl Rewrite<Id> for Timer {
    fn rewrite<S>(&self, _plan: &RewritePlan<Id, S>) -> Self {
        self.clone()
    }
}

impl Rewrite<Id> for ModelCfg {
    fn rewrite<S>(&self, _plan: &RewritePlan<Id, S>) -> Self {
        self.clone()
    }
}
