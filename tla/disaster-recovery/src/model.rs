extern crate stateright;
use stateright::{actor::*, util::HashableHashSet};
use std::borrow::Cow;

type Txid = u64;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct GossipStruct {
    pub src: Id,
    pub txid: Txid,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VoteStruct {
    pub src: Id,
    pub recv: HashableHashSet<GossipStruct>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Msg {
    Gossip(GossipStruct),
    Vote(VoteStruct),
    IAmOpen(Id),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Timer {
    ElectionTimeout,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum NextStep {
    Vote,
    OpenJoin,
    Open { timeout: bool },
    Join,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct State {
    pub next_step: NextStep,
    pub gossips: HashableHashSet<GossipStruct>,
    pub votes: HashableHashSet<VoteStruct>,
    pub submitted_vote: Option<(Id, VoteStruct)>,
    pub txid: Txid,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Node {
    pub peers: HashableHashSet<Id>,
}

impl Node {
    fn vote_for_max<'a>(gossips: &HashableHashSet<GossipStruct>, id: Id) -> (Id, VoteStruct) {
        let dst = gossips
            .iter()
            .max_by_key(|g| (g.txid, g.src))
            .unwrap()
            .src;
        let vote = VoteStruct {
            src: id,
            recv: gossips.clone(),
        };
        return (dst, vote);
    }

    fn other_peers(&self, id: Id) -> Vec<Id> {
        self.peers.iter().filter(|&&p| p != id).cloned().collect()
    }

    fn advance_step(&self, state: &mut State, o: &mut Out<Self>, id: Id, timeout: bool) -> bool {
        match state.next_step {
            NextStep::Vote if state.gossips.len() == self.peers.len() || timeout => {
                let (dst, vote) = Node::vote_for_max(&state.gossips, id);
                state.submitted_vote = Some((dst, vote.clone()));
                if dst == id {
                    state.votes.insert(vote);
                } else {
                    o.send(dst, Msg::Vote(vote));
                }
                state.next_step = NextStep::OpenJoin;
                return true;
            }
            NextStep::OpenJoin if state.votes.len() >= (self.peers.len() + 1) / 2 || timeout => {
                state.next_step = NextStep::Open { timeout };
                o.broadcast(&self.other_peers(id), &Msg::IAmOpen(id));
                return true;
            }
            _ => false,
        }
    }

    fn advance_several(&self, state: &mut State, o: &mut Out<Self>, id: Id, timeout: bool) {
        while self.advance_step(state, o, id, timeout) {}
    }
}

impl Actor for Node {
    type Msg = Msg;
    type State = State;
    type Timer = Timer;
    type Storage = ();
    type Random = ();

    fn on_start(&self, id: Id, _storage: &Option<Self::Storage>, o: &mut Out<Self>) -> Self::State {
        let txid = usize::from(id) as Txid; // Use id as txid for simplicity
        let gossip = GossipStruct { src: id, txid };
        let mut gossips = HashableHashSet::new();
        gossips.insert(gossip.clone());
        let mut state = State {
            next_step: NextStep::Vote,
            gossips,
            votes: HashableHashSet::new(),
            submitted_vote: None,
            txid: usize::from(id) as Txid,
        };
        o.broadcast(&self.other_peers(id), &Msg::Gossip(gossip));
        o.set_timer(Timer::ElectionTimeout, model_timeout());
        self.advance_several(&mut state, o, id, false);
        return state;
    }

    fn on_timeout(&self, id: Id, state: &mut Cow<Self::State>, timer: &Timer, o: &mut Out<Self>) {
        match timer {
            Timer::ElectionTimeout => match state.next_step {
                NextStep::Vote if !state.gossips.is_empty() => {
                    let state = state.to_mut();
                    self.advance_several(state, o, id, true);
                    o.set_timer(Timer::ElectionTimeout, model_timeout());
                }
                NextStep::OpenJoin if !state.votes.is_empty() => {
                    let state = state.to_mut();
                    self.advance_several(state, o, id, true);
                }
                _ => {
                    o.set_timer(Timer::ElectionTimeout, model_timeout());
                }
            },
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
            Msg::IAmOpen(_) => {
                if !matches!(state.next_step, NextStep::Open { .. }) {
                    state.next_step = NextStep::Join;
                }
            }
        };
        self.advance_several(state, o, id, false);
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
                    .map(|_| Node {
                        peers: peers.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
            //.init_network(Network::new_ordered([]))
            .init_network(Network::new_unordered_nonduplicating([]))
            .lossy_network(LossyNetwork::No)
    }
}
