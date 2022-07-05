TLA+ model of CCF's Raft modifications
======================================

CCF implements some modifications to Raft as it was originally proposed by Ongaro and Ousterhout. Specifically, CCF constrains that only appended entries that were signed by the primary can be committed. Any other entry that has not been globally committed is rolled back. Additionally, the CCF implementation introduced a variant of the reconfiguration that is different from the one proposed by the original Raft paper. In CCF CFT, reconfigurations are  done via one transaction (as described :doc:`here </architecture/consensus/1tx-reconfig>`).


The TLA+ specification models the intended behavior of Raft as it is modified for CCF. Below, we explain several core parts of the specification in more detail.

You can find the full specification in the :ccf_repo:`tla/` folder and more information on TLA+ `here <http://lamport.azurewebsites.net/tla/tla.html>`_. Several good resources exist online, one good example is `this guide <https://www.learntla.com>`_.


Building blocks of the TLA+ spec
--------------------------------
The core model is maintained in the :ccf_repo:`tla/raft_spec/ccfraft.tla` file, however the constants defined in this file are controlled through the model check file :ccf_repo:`tla/raft_spec/MCraft.tla`.

This file controls the constants as seen below. In addition to basic settings of how many nodes are to be model checked and their initial configuration, the model allows to place additional limitations on the state space of the program.

.. literalinclude:: ../../tla/raft_spec/MCraft.tla
    :language: text
    :start-after: SNIPPET_START: mc_config
    :end-before: SNIPPET_END: mc_config

Possible state transitions in the model
---------------------------------------
During the model check, the model checker will exhaustively search through all possible state transitions. The below snippet defines the possible state transitions at each step. Each of these transitions has additional constraints that have to be fulfilled for the state to be an allowed step. For example, ``BecomeLeader`` is only a possible step if the selected node has enough votes to do so.

.. literalinclude:: ../../tla/raft_spec/ccfraft.tla
    :language: text
    :start-after: SNIPPET_START: next_states
    :end-before: SNIPPET_END: next_states


Variables and their initial state
---------------------------------
The model uses multiple variables that are initialized as seen below. Most variables are used as a TLA function which behaves similiar to a Map as known from Python or other programming languages. These variables then map each node to a given value, for example the state variable which maps each node to either ``Follower``, ``Leader``, ``Retired``, or ``Pending``. In the initial state shown below, all nodes states are set to the ``InitialConfig`` that is set in ``MCraft.tla``.

.. literalinclude:: ../../tla/raft_spec/ccfraft.tla
    :language: text
    :start-after: SNIPPET_START: init_values
    :end-before: SNIPPET_END: init_values

Basic functions and log changes
-------------------------------
Below, we shortly describe some basic functionality of the Raft model. Note that this is only a selection of the model, please refer to the full model for a full picture.

Timeout
~~~~~~~

Since TLA does not model time, any node can time out at any moment as a next step. Since this may lead to an infinite state space, we limited the maximum term any node can reach. While this would be overly constraining in any actual program, the model checker will ensure to also explore those states that are feasible within these limits. Since interesting traces can already be generated with one or better two term changes, this approach is feasible to model reconfigurations and check persistence.

.. literalinclude:: ../../tla/raft_spec/ccfraft.tla
    :language: text
    :start-after: SNIPPET_START: timeout
    :end-before: SNIPPET_END: timeout

Signing of log entries
~~~~~~~~~~~~~~~~~~~~~~

In CCF, the leader periodically signs the latest log prefix. Only these signatures are committable in CCF. We model this via special ``TypeSignature`` log entries and ensure that the commitIndex can only be moved to these special entries.

.. literalinclude:: ../../tla/raft_spec/ccfraft.tla
    :language: text
    :start-after: SNIPPET_START: signing
    :end-before: SNIPPET_END: signing

Reconfiguration steps
---------------------

The one transaction reconfiguration is already described :doc:`here </architecture/consensus/1tx-reconfig>`. In the TLA model, a reconfiguration is initiated by the Leader which appends an arbitrary new configuration to its own log. This also triggers a change in the ``Configurations`` variable which keeps track of all running configurations.

In the following, this ``Configurations`` variable is then checked to calculate a quorum and to check which nodes should be contacted or received messages from.

.. literalinclude:: ../../tla/raft_spec/ccfraft.tla
    :language: text
    :start-after: SNIPPET_START: reconfig
    :end-before: SNIPPET_END: reconfig
