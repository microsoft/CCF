TLA+ Specifications
===================

The CCF repository includes two formal specification in TLA+ of CCF:

* :ccf_repo:`tla/consistency` which models CCF at a high level of abstraction to test the consistency model exposed to the clients, and 
* :ccf_repo:`tla/consensus` which models in detail the custom distributed consensus protocol implemented in CCF.

CCF implements various modifications to Raft as it was originally proposed by Ongaro and Ousterhout. Specifically, CCF constrains that only appended entries that were *signed* by the primary can be committed. Any other entry that has *not* been signed is rolled back. Additionally, the CCF implementation introduced a variant of the reconfiguration that is different from the one proposed by the original Raft paper, reconfigurations are done atomically and via one transaction (as described :doc:`here </architecture/consensus/1tx-reconfig>`). The TLA+ consensus specification models the intended behavior of Raft as it is modified for CCF. 

You can find the full specifications in the :ccf_repo:`tla/` directory and more information on TLA+ `here <http://lamport.azurewebsites.net/tla/tla.html>`_. Several good resources exist online, one good example is Lamport's `Specifying Systems <https://lamport.azurewebsites.net/tla/book.html>`_.

Running the model checker
-------------------------

The specifications in this repository are implemented for and were checked with the `TLC <http://lamport.azurewebsites.net/tla/tools.html>`_ model checker, specifically with the nightly build of TLC. The model checking files are additionally meant to be run via the VSCode plug-in or the CLI and not through the toolbox. The best way to get started is to use the VSCode plugin. Otherwise, the scripts in this folder allow you to run TLC using the CLI easily.

To download and then run TLC, simply execute:

.. code-block:: bash

    $ cd tla
    $ python install_deps.py
    $ ./tlc.sh consensus/MCccfraft.tla

.. tip::  TLC works best if it can utilize all system resources. Use the ``-workers auto`` option to use all cores. 

You can also check the consensus specification including reconfiguration as follows:

.. code-block:: bash

    $ ./tlc.sh consensus/MCccfraft.tla -config consensus/MCccfraftWithReconfig.cfg

Using TLC to exhaustively check our models can take any time between minutes (for small configurations) and days (especially for the full consensus model with reconfiguration) on a 128 core VM (specifically, we used an `Azure HBv3 instance <https://docs.microsoft.com/en-us/azure/virtual-machines/hbv3-series>`_.

.. tip::  During development and testing, it helps to use simulation mode which performs random walks over the state space (instead of the default exhaustive search that can be quite slow). Turn on the simulation mode with ``-simulate -depth 100`` (using a large number as a maximum depth). Note that this is not exhaustive and never completes (but can find errors in minutes instead of hours).