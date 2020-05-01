Constitution
============

The :term:`Constitution` defines the set of rules and conditions (as a Lua script) that members must follow for their proposals to be accepted. For example, in a CCF network governed by `4` members, a strict majority constitution would only execute proposals once `3` members (`4/2 + 1`) have voted for that proposal.

Votes for the proposal are evaluated by the constitution's ``pass`` function. If the `pass` function returns ``true``, the vote is passed, and its consequences are applied to the KV in a transaction.

Examples of constitution include (see :ref:`members/constitution:Models` for further details):

- Strict majority (`simple constitution`_) that implements a "one-member, one-vote" constitution, with a majority rule. Votes on so-called sensitive tables, such as the one containing the constitution itself, require unanimity.
- Strict majority with member veto (`simple constitution with veto`_) similar to the Strict majority constitution, but where each member is allowed to veto any proposal.
- Operating member + strict majority (`operating member constitution`_) that extends the "strict majority" constitution by defining an operating member allowed to add new nodes to the network, retire existing ones, and allow new versions of the code.

Once the initial set of members have agreed on a constitution, the corresponding Lua file can be given to operators to create a new network (see :ref:`operators/start_network:Starting a New Network`).

.. note:: The constitution can always be updated after the CCF network has been opened, subject to the existing constitution rules.

Models
------

The operators of a CCF network do not necessarily overlap with the members of that network. Although the scriptability of the governance model effectively allows a large number of possible arrangements, the following two schemes seem most likely:

Non-member operators
~~~~~~~~~~~~~~~~~~~~

It is possible for a set of operators to host a CCF network without being members. These operators could:

- Start the network
- Hand it over to the members for them to Open (see :ref:`members/open_network:Opening a network`)

In case of catastrophic failure, operators could also:

- Start a network in recovery mode from the ledger
- Hand it over to the members for them to Open (see :ref:`members/accepting_recovery_and_submitting_shares:Accepting Recovery`)

Finally, operators could:

-	Propose new nodes (TR, Section IV D)
-	Notify the members, who would have to review and vote on the proposal

Operators would not be able to add or remove members or users to the service. They would not be able to update the code of the service (and therefore apply security patches). Because they could propose new nodes, but would require member votes before nodes are allowed to participate in the network, the operators' ability to mitigate node failures may be limited and delayed.

This model keeps operators out of the trust boundary for the service.

Operating members
~~~~~~~~~~~~~~~~~

If network operators are made members, they could have the ability to:

-	Update code (in particular, apply security patches)
-	Add and remove nodes to and from the network

Essentially, operators gain the ability to fix security issues and mitigate service degradation of the network. In this situation however, the operator is inside the trust boundary.

The constitution can limit or remove the operating members' ability to:

-	Add and remove members and users
-	Complete a recovery

.. note:: These limits are weakened by the operators' ability to update the code. A code update could contain changes that allow the operator to bypass constitution restrictions. Work is in progress to propose a service that would effectively mitigate this problem. In the absence of code updates however, other members of the service could trust that the operating members have not added or removed members and users, and have not executed a recovery.

This `operating member constitution`_ shows how some members can be made operators.

.. _simple constitution: https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov.lua

.. _operating member constitution: https://github.com/microsoft/CCF/blob/master/src/runtime_config/operator_gov.lua

.. _simple constitution with veto: https://github.com/microsoft/CCF/blob/master/src/runtime_config/gov_veto.lua