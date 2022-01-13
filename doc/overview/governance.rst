Governance
==========

Governance rules for a CCF network are defined in a JavaScript module called the :term:`Constitution`.

It typically contains the following four elements:

1. A set of executable actions, which can be proposed by members and submitted to a vote.
2. A ``validate()`` function, used to check that proposals submitted by members are well-formed.
3. A ``resolve()`` function, used to evaluate ballots submitted by members for a proposal, and decide whether to apply it.
4. An ``apply()`` function, called if a proposal has been successfully accepted.

``resolve()`` can be used to implement a range of governance models.
For example, in a CCF network governed by `4` equal members, a strict majority ``resolve()`` would only applies proposals once `3` members (`4/2 + 1`) have voted in favour.

Sample implementations of ``resolve()`` include (see `Models`_ for further details):

- Strict majority (`simple constitution`_) that implements a "one-member, one-vote" constitution, with a majority rule.
- Strict majority with member veto (`simple constitution with veto`_) similar to the Strict majority constitution, but where each member is allowed to veto any proposal.
- Operating member + strict majority (`operating member constitution`_) that extends the "strict majority" constitution by defining an operating member allowed to add new nodes to the network, retire existing ones, and allow new versions of the code.

Once the initial set of members have agreed on a constitution, the corresponding JavaScript file can be given to operators to create a new network (see :doc:`/operations/start_network`).

.. note:: The constitution can always be updated after the CCF network has been opened, subject to the existing constitution rules.

Models
------

The operators of a CCF network do not necessarily overlap with the members of that network. Although the scriptability of the governance model effectively allows a large number of possible arrangements, the following two schemes seem most likely:

Non-member operators
~~~~~~~~~~~~~~~~~~~~

It is possible for a set of operators to host a CCF network without being members. These operators could:

- Start the network
- Hand it over to the members for them to Open (see :doc:`/governance/open_network`)

In case of catastrophic failure, operators could also:

- Start a network in recovery mode from the ledger
- Hand it over to the members for them to Open (see :doc:`/governance/accept_recovery`)

Finally, operators could:

-	Propose new nodes
-	Notify the members, who would have to review and vote on the proposal

Operators would not be able to add or remove members or users to the service. They would not be able to update the code of the service (and therefore apply security patches). Because they could propose new nodes, but would require member votes before nodes are allowed to participate in the network, the operators' ability to mitigate node failures may be limited and delayed.

This model keeps operators completely out of the trust boundary for the service.

Operating members
~~~~~~~~~~~~~~~~~

If network operators are members, they can have the ability to:

-	Update code (in particular, apply security patches)
-	Add and remove nodes to and from the network

Essentially, operators have the ability to fix security issues and mitigate service degradation of the network. In this situation however, the operator is inside the trust boundary.

The constitution can limit or remove the operating members' ability to:

-	Add and remove members and users
-	Complete a recovery

.. note:: These limits are weakened by the operators' ability to update the code. A code update could contain changes that allow the operator to bypass constitution restrictions. Work is in progress to propose a service that would effectively mitigate this problem. In the absence of code updates however, other members of the service could trust that the operating members have not added or removed members and users, and have not executed a recovery.

This `operating member constitution`_ shows how some members can be made operators.

.. _simple constitution: https://github.com/microsoft/CCF/blob/main/samples/constitutions/default/resolve.js
.. _operating member constitution: https://github.com/microsoft/CCF/blob/main/samples/constitutions/operator/resolve.js
.. _simple constitution with veto: https://github.com/microsoft/CCF/blob/main/samples/constitutions/veto/resolve.js