Certificates
============

Since 2.x releases, the validity period of certificates is no longer hardcoded. This page describes how the validity period can instead be set by operators, and renewed by members.

.. note:: The granularity for the validity period of nodes certificates is one day.

Node Certificates
-----------------

At startup, operators can set the validity period for a node using the ``--initial-node-cert-validity-days`` CLI argument. The default value is set to 1 day and it is expected that members will issue a proposal to renew the certificate before it expires, when the service is open. Initial nodes certificates are valid from the current system time when the ``cchost`` executable is launched.

The ``--max-allowed-node-cert-validity-days`` CLI argument (defaults to 365 days) can be used to set the maximum allowed validity period for nodes certificates when they are renewed by members. It is used as the default value for the validity period when a node certificate is renewed but the validity period is omitted.

.. tip:: Once a node certificate has expired, clients will no longer trust the node serving their request. It is expected that operators and members will monitor the certificate validity dates with regards to current time and renew the node certificate before expiration. See :ref:`governance/common_member_operations:Renewing Node Certificate` for more details.