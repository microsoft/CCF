# Self-healing-open specification in [stateright](https://github.com/stateright/stateright)

The properties are specified in [main.rs](./src/main.rs), while the model is specified in [model.rs](./src/model.rs).

Due to stateright being executable, there is little syntactic sugar, and so there is quite a bit of boilerplate.
The functional parts of the specification are in `advance_step`, `on_start`, `on_timeout` and `on_msg`.

The specification can be checked from the command line via `cargo run check`.

However, a more useful UX is via the web-view which is hosted locally via `cargo run serve`.
This allows you to explore the specification actions interactively, and the checker can be exhaustively run using the `Run to completion` button, which should find several useful examples of states where the network is opened, and where a deadlock is reached.

## Exporting the state graph

`cargo run --quiet -- export --nodes <N> [-o <file>]` exhaustively enumerates the reachable
state graph (via the public `stateright::Model` interface, i.e. `init_states`/`next_steps`)
and writes it to `<file>` (or stdout) in the shared `ccf-legacy-dr-graph-v1` TSV contract, so
it can be diffed against an independent re-implementation of the same model (e.g. in Python
or Lean). The encoder (`src/export.rs`) never uses `Debug` formatting, so output is insulated
from field order, hash-set iteration order, and library-version changes. Full grammar and
design notes are documented in the module doc comment at the top of `src/export.rs`; summary:

```text
format	ccf-legacy-dr-graph-v1
nodes	<N>
init	<ID>
state	<ID>	<STATE_KEY>	<BITSTRING>   (one per reachable state, ascending <ID>)
edge	<SRC_ID>	<ACTION>	<DST_ID>      (one per reachable transition, sorted)
```

- `<ID>` is a dense integer (`0..N_STATES`) assigned by sorting every reachable state's
  `<STATE_KEY>` lexicographically -- _not_ BFS/discovery order -- so numbering is a pure
  function of the reachable state set. Edges reference states only by `<ID>` (not by
  repeating `<STATE_KEY>`), since e.g. `n=3` already has 105,558 states / 552,282 edges and
  repeating full state keys per edge does not scale. `edge` records are sorted by the tuple
  `(<SRC_ID>, <ACTION> text, <DST_ID>)` -- numeric on the ids, lexicographic on the action --
  and de-duplicated.
- `<BITSTRING>` is 9 chars of `1`/`0`, one per predicate registered via
  `ActorModel::property` (`model.properties`), in registration order -- the exact same `fn`
  pointers used by `check`/`serve`, so the export can never drift from their semantics.
- `<STATE_KEY>` is `S([ACTORS],[TIMERS],[ENVELOPES])`: `ACTORS` are semicolon-separated
  `s(PHASE,[GOSSIPS],[VOTES],SUBMITTED,txid)` records (`PHASE` in `vote`/`openjoin`/`open0`/
  `open1`/`join`), `TIMERS` are the ids of actors with an active election timeout, and
  `ENVELOPES` are `e(src,dst,msg)#count` in flight. `history`/`random_choices`/
  `actor_storages` (always the unit value `()` for this model) and `crashed` (always all
  `false`, since `max_crashes` is never set above `0`) are omitted, as they carry no
  information here.
- `<ACTION>` is `deliver(src,dst,msg)` or `timeout(id,election)`.
- Set elements (`GOSSIPS`, `VOTES`) and `ENVELOPES` are ordered using the real Rust
  `#[derive(Ord)]` implementations of `GossipStruct`/`VoteStruct`/`Envelope<Msg>` (not a
  string sort).
- Per `Model::next_state`'s "`None` = no-op" contract, only actions where `next_state`
  returns `Some` produce an `edge` line (`Model::next_steps`'s default implementation
  already filters these out).

`--nodes` is an alias for the existing `--n-nodes`/`-n` flag, and (being a global clap
argument) is accepted either before or after the subcommand, so existing invocations
(`cargo run -- --n-nodes 3 check`, `cargo run check`, `cargo run -- --n-nodes 3 serve`) keep
working unchanged alongside `cargo run --quiet -- export --nodes <N>`.
