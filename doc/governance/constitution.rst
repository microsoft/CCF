Constitution
============

The constitution for a CCF service is implemented as a set of JS scripts. These scripts can be submitted at network startup in the ``start.constitution_files`` configuration entry, or updated by a governance proposal. They will be concatenated into a single entry in the ``public:ccf.gov.constitution`` table, and should export 3 named functions:

    - ``validate``: This takes the raw body of a proposal and checks that this proposal is correctly formed. For instance it may parse the body as JSON, extract the list of proposed actions, and confirm that each action is known and has parameters matching the expected schema. This should not interact with the KV, and should operate purely on the given proposal.
    - ``resolve``: This takes a proposal and the votes (the results of ballot scripts) which have been submitted against it, and determines whether the proposal should be accepted or rejected. In the simple case this might simply accept proposals after a majority of members have voted in favour. It could also examine member data to give each member a different role or weight, or have different thresholds for each action. This has read-only access to the KV.
    - ``apply``: This takes a proposal which has been accepted by ``resolve``, and should make the proposed changes to the service's state. For instance if the proposal added a new user this should extract their cert and data from the proposal and write them to the appropriate KV tables. This has full read-write access to the KV.

Sample constitutions are available in the :ccf_repo:`samples/constitutions/` folder and include the default implementation of ``apply`` which parses a JSON object from the proposal body, and then delegates the application of each action within the proposal to a named entry from ``actions.js``:

.. literalinclude:: ../../samples/constitutions/default/apply.js
    :language: js

There are also more involved examples such as ``veto/resolve.js``. This accepts proposals when a majority of members vote in favour, but also allows any single member to veto the proposal, marking it ``Rejected`` after a single vote against:

.. literalinclude:: ../../samples/constitutions/veto/resolve.js
    :language: js

There are also examples for specific member roles such as ``operator/resolve.js`` ``operator_provisioner/resolve.js``. Operators are allowed to add and remove nodes from the network without a majority vote, and operator provisioners are allowed to endorse members to be operators, which allows customers to control the operators in the case of disaster recovery.

.. literalinclude:: ../../samples/constitutions/operator_provisioner/resolve.js
    :language: js