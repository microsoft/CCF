# Reduced Raft spec

The reduced Raft spec is a subset of the full Raft spec and is only a minor change from the [original Raft
spec](https://github.com/ongardie/raft.tla/blob/master/raft.tla). Essentially, the changes are:

- Added entry signing through the leader.
- Only signed entries are committable.
- Certain constraints and limits placed on the state space to make model checking feasible.

However, the full Raft spec also implements reconfiguration which can have a big impact on the persistence guarantees
provided by Raft. This reduced spec is only provided as a starting point for a leaner Raft spec that may not want to
model the whole range of functionality as it is currently implemented in CCF.
