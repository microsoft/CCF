Governance
==========

This section describes how a consortium of trusted :term:`Members` governs an existing CCF network. It explains how members can submit proposals to CCF and how these proposals are accepted based on the rules defined in the :term:`Constitution`.

Before creating a new CCF network, the identity of the initial member(s) of the consortium must be generated. See :ref:`governance/adding_member:Generating Member Keys and Certificates`.

.. grid:: 1 2 2 2
    :gutter: 3

    .. grid-item-card:: :fas:`scroll` :doc:`constitution`

        Governance in CCF is implemented as a scriptable constitution.

    .. grid-item-card:: :fas:`hand-paper` :doc:`proposals`

        Governance changes are submitted to a network as Proposals, and put to a vote from members.

    .. grid-item-card:: :fas:`box-open` :doc:`open_network`

        Opening a freshly created network to user activity is a proposal.

    .. grid-item-card:: :fas:`box-open` :doc:`common_member_operations`

        Frequently used member operations.

    .. grid-item-card:: :fas:`user-plus` :doc:`adding_member`

        Adding a new member to the consortium.

    .. grid-item-card:: :fas:`key` :doc:`hsm_keys`

        Storing member keys in HSM.

    .. grid-item-card:: :fas:`terminal` :doc:`member_rpc_api`

        OpenAPI schema for member RPC API.

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
    hsm_keys
    member_rpc_api



