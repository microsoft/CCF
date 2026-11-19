Governance
==========

This section describes how a consortium of trusted :term:`Members` governs an existing CCF network. It explains how members can submit proposals to CCF and how these proposals are accepted based on the rules defined in the :term:`Constitution`.

Before creating a new CCF network, the identity of the initial member(s) of the consortium must be generated. See :ref:`governance/adding_member:Generating Member Keys and Certificates`.

.. grid:: 1 2 2 2
    :gutter: 3

    .. grid-item-card:: :fas:`scroll` :doc:`constitution`

        Define governance using a scriptable constitution.

    .. grid-item-card:: :fas:`hand-paper` :doc:`proposals`

        Submit governance proposals and vote on them as a member.

    .. grid-item-card:: :fas:`box-open` :doc:`open_network`

        Open a freshly created network to user activity.

    .. grid-item-card:: :fas:`box-open` :doc:`common_member_operations`

        Perform common member operations.

    .. grid-item-card:: :fas:`user-plus` :doc:`adding_member`

        Add a new member to the consortium.

    .. grid-item-card:: :fas:`arrows-rotate` :doc:`migrating_identity_ids`

        Migrate existing users and members to ``did:key`` IDs.

    .. grid-item-card:: :fas:`key` :doc:`hsm_keys`

        Store member keys in an HSM.

    .. grid-item-card:: :fas:`terminal` :doc:`member_rpc_api`

        Consult the member API reference.

.. toctree::
    :hidden:
    :maxdepth: 1

    constitution
    proposals
    js_runtime
    open_network
    accept_recovery
    common_member_operations
    adding_member
    migrating_identity_ids
    hsm_keys
    member_rpc_api

