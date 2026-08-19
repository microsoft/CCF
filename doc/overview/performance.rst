Performance
===========

Overview
--------

CCF pairs strong confidentiality guarantees with :ccf_repo:`very high performance </CCF-PAPER-VLDB-2023.pdf>`. CCF can sustain high transaction throughput, while also reaching consensus over commits with low latency.

There are several performance metrics in the CI test suite to ensure this, ranging from micro-benchmarks of critical systems to end-to-end tests measuring peak throughput. These are run against every PR and commit to the main branch. You can also run these locally to test the configuration of your machines, and use them as a basis for creating performance tests of your own CCF application.

Micro-benchmarks
----------------

The micro-benchmark tests can be run from the CCF build directory:

.. code-block:: bash

    ./tests.sh -VV -L "bench"

These test performance-critical features of CCF such as certificate verification and KV alterations.


End-to-end performance tests
----------------------------

The end-to-end service performance tests can also be from the CCF build directory:

.. code-block:: bash

    ./tests.sh -VV -L "perf" -C "perf"

Each of these tests creates a temporary CCF service on the local machine, then sends a high volume of transactions to measure peak and average throughput. The Python test wrappers print summary statistics including a transaction rate histogram when the test completes.

For a finer grained view of performance the clients in these tests can also dump the precise times each transaction was sent and its response received, for later analysis. The ``samples`` folder contains a ``plot_tx_times`` Python script which produces plots from this data.

Profiling
---------

End-to-end performance tests can be run with the Linux utility ``perf``
attached to the nodes to produce profile data. Set the ``CCF_PERF`` environment
variable before running a test to enable this:

.. code-block:: bash

    CCF_PERF=1 ./tests.sh -VV -R '^pi_basic$' -C perf

By default, nodes run under
``perf record -m 16 -e task-clock:u -F 99 -g --call-graph dwarf --quiet``.
These options keep profiling reliable and useful in development containers:

- ``-m 16`` limits the mmap data buffer to 16 pages, avoiding failures caused
    by the low ``perf_event_mlock_kb`` limit in constrained environments such as
    Codespaces.
- ``-e task-clock:u`` selects the software task-clock event and records only
    user-space execution. Unlike hardware counters, this event remains available
    when the host does not expose a hardware PMU; excluding the kernel also
    avoids inaccessible kernel symbols.
- ``-F 99`` samples at 99 Hz, bounding collection overhead while retaining
    enough detail for whole-test profiles.
- ``-g --call-graph dwarf`` records call chains using DWARF stack unwinding,
    which preserves the C++ stacks needed by ``perf report`` and flame graphs.
- ``--quiet`` suppresses non-fatal recording warnings that would otherwise be
    mixed into each node's error log.

Set ``CCF_PERF_ARGS`` to replace these recording options. The harness always
appends ``-o perf.data --`` so that each node writes to a predictable path in
its workspace directory and the remaining arguments invoke the node.

The profiling process requires permission to use ``perf_event_open``. The
CCF development containers install ``perf`` and grant the ``PERFMON``
capability. Hardware performance counters may still be unavailable when the
host does not expose a hardware PMU; the default software task-clock event
remains available in that case.

Inspect the recorded profile directly with:

.. code-block:: bash

    perf report --stdio --no-children -i workspace/pi_basic_0/perf.data

To render a flame graph with the Inferno tools, run:

.. code-block:: bash

    perf script -i workspace/pi_basic_0/perf.data \
      | inferno-collapse-perf \
      | inferno-flamegraph > pi_basic_flamegraph.svg
