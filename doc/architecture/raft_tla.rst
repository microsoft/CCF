TLA+ Specifications
===================

The CCF repository includes two formal specification in TLA+ of CCF:

* :ccf_repo:`tla/consistency` which models CCF at a high level of abstraction to test the consistency model exposed to the clients, and 
* :ccf_repo:`tla/consensus` which models in detail the custom distributed consensus protocol implemented in CCF.

CCF implements various modifications to Raft as it was originally proposed by Ongaro and Ousterhout. Specifically, CCF constrains that only appended entries that were *signed* by the primary can be committed. Any other entry that has *not* been signed is rolled back. The TLA+ consensus specification models the intended behavior of Raft as it is modified for CCF. 

You can find the full specifications in the :ccf_repo:`tla/` directory and more information on TLA+ `here <http://lamport.azurewebsites.net/tla/tla.html>`_. Several good resources exist online, one good example is Lamport's `Specifying Systems <https://lamport.azurewebsites.net/tla/book.html>`_.

Running the model checker
-------------------------

The specifications in this repository are implemented for and were checked with the `TLC <http://lamport.azurewebsites.net/tla/tools.html>`_ model checker, specifically with the nightly build of TLC. The model checking files are additionally meant to be run via the VSCode plug-in or the CLI and not through the toolbox. The best way to get started is to use the VSCode plugin. Otherwise, the scripts in this folder allow you to run TLC using the CLI easily.

To download and then run TLC, simply execute:

.. code-block:: bash

    $ cd tla
    $ python install_deps.py
    $ ./tlc.py consensus/MCccfraft.tla

.. tip::  TLC works best if it can utilize all system resources. Use the ``-workers auto`` option to use all cores. 

You can also check the consensus specification including reconfiguration as follows:

.. code-block:: bash

    $ ./tlc.py --term-count 2 --request-count 0 --raft-configs 3C2N --disable-check-quorum consensus/MCccfraft.tla

Using TLC to exhaustively check our models can take any time between minutes (for small configurations) and days (especially for the full consensus model with reconfiguration) on a 128 core VM (specifically, we used an `Azure HBv3 instance <https://docs.microsoft.com/en-us/azure/virtual-machines/hbv3-series>`_.

.. tip::  During development and testing, it helps to use simulation mode which performs random walks over the state space (instead of the default exhaustive search that can be quite slow). Turn on the simulation mode with ``-simulate -depth 100`` (using a large number as a maximum depth). Note that this is not exhaustive and never completes (but can find errors in minutes instead of hours).

.. tip:: You can open a `GitHub Codespace <https://github.com/codespaces/new?hide_repo_select=true&ref=main&repo=180112558&machine=xLargePremiumLinux&devcontainer_path=.devcontainer%2Ftlaplus%2Fdevcontainer.json&location=WestEurope>`_ to run the model checking and validation.

Trace validation
----------------

It is possible to produce fresh traces quickly from the driver by running the ``make_traces.sh`` script from the ``tla`` directory.

Calling the trace validation on, for example, the ``append`` scenario can then be done with ``./tlc.py --driver-trace ../build/append.ndjson consensus/Traceccfraft.tla``.

Generating a trace of a scenario and validating it in one go can be done with ``./tlc.py --workers 1 tv --scenario ../tests/raft_scenarios/append consensus/Traceccfraft.tla``.
This runs the raft_driver on the scenario, cleans the trace and then validates it against the TLA+ specification.

CCF also provides a command line trace visualizer to aid debugging, for example, the ``append`` scenario can be visualized with ``python ../tests/trace_viz.py ../build/append.ndjson``. 
