# Auto-open specification in [stateright](https://github.com/stateright/stateright)

The properties are specified in [main.rs](./src/main.rs), while the model is specified in [model.rs](./src/model.rs).

Due to stateright being executable, there is little syntactic sugar, and so there is quite a bit of boilerplate.
The functional parts of the specification are in `advance_step`, `on_start`, `on_timeout` and `on_msg`.

The specification can be checked from the command line via `cargo run check`.

However, a more useful UX is via the web-view which is hosted locally via `cargo run serve`.
This allows you to explore the specification actions interactively, and the checker can be exhaustively run using the `Run to completion` button, which should find several useful examples of states where the network is opened, and where a deadlock is reached.


