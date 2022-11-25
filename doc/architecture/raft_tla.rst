TLA+ Specification
==================

The CCF repository includes a formal specification in TLA+ of CCF's consensus algorithm, which is a variant of Raft.

This specification serves two purposes:

1. To catch problematic edge cases in our version of the Raft protocol that may not be trivially found or that may not be covered by tests.
2. To serve as a formal future-proof specification of the protocol as it is intended to function.

The first purpose can be achieved by running the specification with a model checker. While we used `TLC <http://lamport.azurewebsites.net/tla/tools.html>`_ which comes built-in with the TLA+ tools, any model checker that works with TLA+ should be possible to make run.

The second purpose is achieved simply with the TLA+ code. However, it is important to understand that the **TLA+ specification has no binding to the actual implementation**. This means that any change in the Raft implementation after the last modification of this specification may not be reflected and can still contain unexpected edge cases. However, comments in the TLA+ code are meant to help make this transition easier. Overall, we expect the CI tests in addition to this model checking to give us a good coverage of the behaviors to expect.

CCF implements various modifications to Raft as it was originally proposed by Ongaro and Ousterhout. Specifically, CCF constrains that only appended entries that were *signed* by the primary can be committed. Any other entry that has *not* been signed is rolled back. Additionally, the CCF implementation introduced a variant of the reconfiguration that is different from the one proposed by the original Raft paper. By default, reconfigurations are done via one transaction (as described :doc:`here </architecture/consensus/1tx-reconfig>`).

The TLA+ specification models the intended behavior of Raft as it is modified for CCF. Below, we explain several core parts of the specification in more detail.

You can find the full specification in the :ccf_repo:`tla/` directory and more information on TLA+ `here <http://lamport.azurewebsites.net/tla/tla.html>`_. Several good resources exist online, one good example is `this guide <https://www.learntla.com>`_.

Running the model checker
-------------------------

The specifications in this repository are implemented for and were checked with the TLC model checker, specifically with the nightly build of TLC. The model checking files are additionally meant to be run via the CLI and not through the toolbox. To make this easier, the scripts in this folder allow you to run TLC easily.

To download and then run TLC, simply execute:

.. code-block:: bash

    $ cd tla
    $ python install_deps.py
    $ ./tlc.sh MCccfraft.tla

You can also check the specification including reconfiguration as follows:

.. code-block:: bash

    $ ./tlc.sh MCccfraftWithReconfig.tla -config MCccfraft.cfg

Running TLC on our models can take any time between minutes (for small configurations) and days (especially for the full model with reconfiguration) on a 128 core VM (specifically, we used an `Azure HBv3 instance <https://docs.microsoft.com/en-us/azure/virtual-machines/hbv3-series>`_.

.. note::  TLC works best if it can utilize all system resources. For this, the ```tlc.sh``` script already uses the ``-workers auto``` option to use all cores. However, depending on your configuration, you may want to allocate more memory to the Java VM. you can do this by modifying the script and changing the values of ``-Xms2G -Xmx2G``` to enforce the specific RAM usage that you need (2GB in this case). Note that it is useful to fix both minimum and maximum value to increase performance.

.. note::  During development, it helps to use simulation mode which performs a depth-first search of the search tree (instead of the default breadth first that is very slow). Turn on the simulation mode with ``-simulate -depth 100000`` (using a very large number as a maximum depth). Note that this mode never completes (but will find errors in minutes instead of hours).

The given specification consists of:

- ``ccfraft.tla`` : The core formal specification that implements CCF Raft.
- ``MCccfraft.tla`` : The model checking implementation for the specification (that uses a static configuration). Sets the constants and can be modified for each run to fine tune the settings, for instance to increase or decrease the size of the model checking.
- ``MCccfraft.cfg`` : The core configuration that defines which invariants are to be checked etc. Usually stays untouched during normal model checking.
- ``MCccfraftWithReconfig.tla``: Analogous to ``MCccfraft.tla`` but with support for reconfiguration.