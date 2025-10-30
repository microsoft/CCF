Certificates
============

This page describes how the validity period of node and service certificates can be set by operators, and renewed by members.

.. note:: The granularity of the validity period of nodes and service certificates is one day.

.. tip:: See :ref:`architecture/cryptography:Identity Keys and Certificates` for a detailed explanation of the relationship between keys and certificates in CCF.

Node Certificates
-----------------

At startup, operators can set the validity period for a node using the ``node_certificate.initial_validity_days`` :doc:`configuration entry </operations/configuration>`. The default value is set to 1 day and it is expected that members will issue a proposal to renew the certificate before it expires, when the service is open. A node's initial certificates are valid from the current system time when the executable is launched.

The ``command.start.service_configuration.maximum_node_certificate_validity_days`` :doc:`configuration entry </operations/configuration>` (defaults to 365 days) can be used to set the maximum allowed validity period for nodes certificates when they are renewed by members. It is used as the default value for the validity period when a node certificate is renewed but the validity period is omitted.

Service-endorsed and self-signed node certificates are set with identical validity periods throughout the lifetime of a node. These certificates are presented to clients by ``Service`` and ``Node`` endorsed RPC interfaces, respectively (see ``rpc_interfaces.endorsement`` :doc:`configuration entry </operations/configuration>`).

.. tip:: Once a node certificate has expired, clients will no longer trust the node serving their request. It is expected that operators and members will monitor the certificate validity dates with regard to current time and renew the node certificate before expiration. See :ref:`governance/common_member_operations:Renewing Node Certificate` for more details.

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

Service Certificate
-------------------

The service certificate is output by the first node of a service at startup at the location specified by the ``command.service_certificate_file`` :doc:`configuration entry </operations/configuration>`. Operators can set the validity period for this certificate using the ``command.start.initial_service_certificate_validity_days`` :doc:`configuration entry </operations/configuration>`. The default value is set to 1 day and it is expected that members will issue :ref:`proposal to renew the certificate before it expires <governance/common_member_operations:Renewing Service Certificate>`, when the service is open. The initial service certificate is valid from the current system time when the first node is started.

The ``command.start.service_configuration.maximum_service_certificate_validity_days`` :doc:`configuration entry </operations/configuration>` (defaults to 365 days) can be used to set the maximum allowed validity period for nodes certificates when they are renewed by members. It is used as the default value for the validity period when the service certificate is renewed but the validity period is omitted.

.. tip::

    - The current service certificate (PEM) can be retrieved by operators via the :http:GET:`/node/network` endpoint (``"service_certificate"`` field).
    - Once renewed, the service certificate should be distributed to clients to be used as the certificate authority (CA) when establishing a TLS connection with any of the nodes part of the CCF network.

The procedure that operators and members should follow is summarised in the following diagram:

.. mermaid::

    gantt

    dateFormat  MM-DD/HH:mm
    axisFormat  %d/%m
    todayMarker off

    section Members
    Service Open By Members + set_service_certificate_validity :milestone, 01-01/15:00, 0d
    Members must renew certs before expiry (set_service_certificate_validity)              :crit, 01-05/15:00, 1d

    section Service <br> Certificate
    Initial Validity Period (24h default): done, 01-01/00:00, 1d
    Post Service Open Validity Period    : 01-01/15:00, 5d
