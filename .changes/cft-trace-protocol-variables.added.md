`ccf.cft` consensus trace events now also carry the protocol variables `voted_for`, `votes_for_me`, `leader_id`, `is_new_follower` and `ticking` as top-level fields, on the events whose code reads or writes them.
See the [consensus trace replay README](lean/consensus/replay/README.md#run-replay) for the encoding.
