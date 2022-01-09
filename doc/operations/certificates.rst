Certificates
============

Since 2.x releases, the validity period of certificates is no longer hardcoded. This page describes how the validity period can instead be set by operators, and renewed by members.

.. note:: The granularity for the validity period of nodes certificates is one day.

Node Certificates
-----------------

At startup, operators can set the validity period for a node using the ``node_certificate.initial_validity_days`` configuration entry. The default value is set to 1 day and it is expected that members will issue a proposal to renew the certificate before it expires, when the service is open. Initial nodes certificates are valid from the current system time when the ``cchost`` executable is launched.

The ``start.service_configuration.maximum_node_certificate_validity_days`` configuration entry (defaults to 365 days) can be used to set the maximum allowed validity period for nodes certificates when they are renewed by members. It is used as the default value for the validity period when a node certificate is renewed but the validity period is omitted.

.. tip:: Once a node certificate has expired, clients will no longer trust the node serving their request. It is expected that operators and members will monitor the certificate validity dates with regards to current time and renew the node certificate before expiration. See :ref:`governance/common_member_operations:Renewing Node Certificate` for more details.

The procedure that operators and members should follow is summarised in the following example. A 3-node service is started by operators and the initial certificate validity period is set by ``node_certificate.initial_validity_days`` (grey). Before these certificates expire, the service is open by members who renew the certificate for each node, via the ``set_all_nodes_certificate_validity`` proposal action, either standalone or bundled with the existing ``transition_service_to_open`` action. When a new node (3) joins the service, members should set the validity period for its certificate when submitting the ``transition_node_to_trusted`` proposal. Finally, operators and members should issue a new proposal to renew soon-to-expire node certificates (red).

.. mermaid::

    gantt

    dateFormat  MM-DD/HH:mm
    axisFormat  %d/%m
    todayMarker off

    section Members
    Service Open By Members + set_all_nodes_certificate_validity :milestone, 01-01/15:00, 0d
    Members trust new node 3 (transition_node_to_trusted)        :milestone, 01-03/15:00, 0d
    Members must renew certs before expiry (set_all_nodes_certificate_validity)              :crit, 01-05/15:00, 1d

    section Node 0
    Initial Validity Period (24h default): done, 01-01/00:00, 1d
    Post Service Open Validity Period    : 01-01/15:00, 5d

    section Node 1
    Initial Validity Period (24h default): done, 01-01/01:00, 1d
    Post Service Open Validity Period    : 01-01/15:00, 5d

    section Node 2
    Initial Validity Period (24h default): done, 01-01/02:00, 1d
    Post Service Open Validity Period    : 01-01/15:00, 5d

    section Node 3
    Initial Validity Period (24h default)      : done, 01-03/00:00, 1d
    New Joiner Validity Period                 : 01-03/15:00, 4d
