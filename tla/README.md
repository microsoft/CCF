# TLA+ specifications

In order to complement the CI tests of CCF, we created a formal specification of the Raft consensus protocol in TLA+.
This specification serves two purposes:

1. To catch problematic edge cases in our version of the Raft protocol that may not be trivially found or that may not be covered by tests.
2. To serve as a formal future-proof specification of the protocol as it is intended to function.

The first purpose can be achieved by running the specification with a model checker. While we used [TLC](http://lamport.azurewebsites.net/tla/tools.html) which comes built-in with the TLA+ tools, any model checker that works with TLA+ should be possible to make run.

The second purpose is achieved simply with the TLA+ code. However, it is important to understand that the **TLA+ specification has no binding to the actual implementation**. This means that any change in the Raft implementation after the last modification of this specification may not be reflected and can still contain unexpected edge cases. However, comments in the TLA+ code are meant to help make this transition easier. Overall, we expect the CI tests in addition to this model checking to give us a good coverage of the behaviors to expect.

## Running the model checker

The specifications in this repository are implemented for and were checked with the TLC model checker, specifically with TLC in [version 1.7.1](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.1). The model checking files are additionally meant to be run via the CLI and not through the toolbox. To make this easier, some bindings for TLC may be helpful (such as these bindings [here](https://github.com/pmer/tla-bin/blob/66c09caa79d1427418e703cf07a5ad7edc72bb96/bin/tlc)).

With a binding of TLC, the models in the subfolders can be run with `tlc MCraft.tla` (or in the case of the full spec that sacrifices liveness checking for a model that can be run with the model checker: `tlc MCraft.tla -deadlock` since deadlocks have to be disabled for that model).

Each model controls its limits in the MCraft.tla file where the constants can be modified to increase or decrease the size of the model checking.

Running TLC on our models can take any time between minutes (for small configurations) and days (especially for the full model with reconfiguration) on a 128 core VM (specifically, we used an [Azure HBv3 instance](https://docs.microsoft.com/en-us/azure/virtual-machines/hbv3-series)).

### A note on TLC performance

TLC works best if it can utilize all system resources. For this, consider using the TLC options `-workers auto` to use all cores and the Java VM options `-Xms435G -Xmx435G` to enforce a specific RAM usage (435GB in this case as provided by the 128 core HBv3 VM).

During development, it helps to use simulation mode which performs a depth-first search of the search tree (instead of the default breadth first that is very slow). Turn on the simulation mode with `-simulate -depth 100000` (using a very large number as a maximum depth). Note that this mode never completes (but will find errors in minutes instead of hours).
