Certificates
============

Since 2.x releases, the validity period of certificates is no longer hardcoded. This page describes how the validity period can instead be set by operators, and renewed by members.

.. note:: The granularity for the validity period of nodes and service certificates is one day.

.. tip:: See :ref:`architecture/cryptography:Identity Keys and Certificates` for a detailed explanation of the relationship between keys and certificates in CCF.

Node Certificates
-----------------

At startup, operators can set the validity period for a node using the ``node_certificate.initial_validity_days`` :doc:`configuration entry </operations/configuration>`. The default value is set to 1 day and it is expected that members will issue a proposal to renew the certificate before it expires, when the service is open. Initial nodes certificates are valid from the current system time when the ``cchost`` executable is launched.

The ``command.start.service_configuration.maximum_node_certificate_validity_days`` :doc:`configuration entry </operations/configuration>` (defaults to 365 days) can be used to set the maximum allowed validity period for nodes certificates when they are renewed by members. It is used as the default value for the validity period when a node certificate is renewed but the validity period is omitted.

Service-endorsed and self-signed node certificates are set with identical validity periods throughout the lifetime of a node. These certificates are presented to clients by ``Service`` and ``Node`` endorsed RPC interfaces, respectively (see ``rpc_interfaces.endorsement`` :doc:`configuration entry </operations/configuration>`).

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

Service Certificate
-------------------

The service certificate is output by the first node of a service at startup at the location specified by the ``command.service_certificate_file`` :doc:`configuration entry </operations/configuration>`. Operators can set the validity period for this certificate using the ``command.start.initial_service_certificate_validity_days`` :doc:`configuration entry </operations/configuration>`. The default value is set to 1 day and it is expected that members will issue :ref:`proposal to renew the certificate before it expires <governance/common_member_operations:Renewing Service Certificate>`, when the service is open. The initial service certificate is valid from the current system time when the ``cchost`` executable is launched.

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


ACME-endorsed TLS certificates
------------------------------

Unendorsed, self-signed (CA) service certificates are a complication for clients as they need to be given a copy of the certificate before they can establish TLS connections to the service, or the service certificate is permanently installed in their trust store. To alleviate this, CCF provides an `ACME <https://en.wikipedia.org/wiki/Automatic_Certificate_Management_Environment>`_ client, which is used to obtain TLS certificates that are endorsed by external certificate authorities. For instance, the `Let's Encrypt <https://letsencrypt.org/>`_ CA is endorsed by a root certificate that is pre-installed on most current operating systems, which means that clients usually have all required certificates to establish TLS connections without further configuration, if the service certificate is endorsed by Let's Encrypt. CCF handles the creation and renewal of ACME certificates, but it requires some configuration:

1. Get a globally reachable DNS name for your CCF network, e.g. ``my-ccf.example.com``, which resolves to the address of at least one node in the network. Multiple nodes or a load balancer address are fine too.

2. ACME `http-01 <https://letsencrypt.org/docs/challenge-types/>`_ challenges require a challenge server to be reachable on port 80 (non-negotiable).
To be able to bind to that port, the ``cchost`` binary may need to be given special permission, e.g. by running ``sudo setcap CAP_NET_BIND_SERVICE=+eip cchost``. Alternatively, port 80 can be redirected to a non-privileged port that ``cchost`` may bind to without special permission.

3. Each interface defined in the ``cchost`` configuration file can be given the name of an ACME configuration to use. The settings of each ACME configuration are defined in ``network.acme`` :doc:`configuration entry </operations/configuration>`. Note that this information is required by *all* nodes as they might have to renew the certificate(s) later. Further, an additional interface for the challenge server is required.

    The various options are as follows:

    .. code-block:: python

        "network": {
            "rpc_interfaces": {
                # ... ,
                "acme_endorsed_interface": {
                    # ... ,
                    "endorsement": {
                        # ... ,
                        "acme_configuration": "my-acme-cfg"
                    }
                },
                "acme_challenge_server_interface": {
                    "bind_address": "...:80",
                    "endorsement": {
                        "authority": "Unsecured"
                    },
                    "accepted_endpoints": [ "/.well-known/acme-challenge/.*" ]
                    # ...
                }
            },
            "acme": {
                "my-acme-cfg": {
                    "ca_certs": [ "-----BEGIN CERTIFICATE-----\nMIIBg ..." ],
                    "directory_url": "https://...",
                    "service_dns_name": "my-ccf.example.com",
                    "alternative_names": [ "www.my-ccf.example.com", ... ]
                    "contact": ["mailto:john@example.com"],
                    "terms_of_service_agreed": true,
                    "challenge_type": "http-01",
                    "challenge_server_interface": "acme_challenge_server_interface"
                }
            }
        }


    - ``ca_certs``: CCF will need to establish https connections with the CA, but does not come with root certificates by default and therefore will fail to establish connections. This setting is populated with one or more such certificates; e.g. for Let's Encrypt this would be their ISRG Root X1 certificate (see `here <https://letsencrypt.org/certificates/>`_) in PEM format.
    - ``directory_url``: This is the main entry point for the ACME protocol. For Let's Encrypt's `staging environment <https://letsencrypt.org/docs/staging-environment/>`_, this is ``https://acme-staging-v02.api.letsencrypt.org/directory``; minus the ``-staging`` for their production environment).
    - ``service_dns_name``: The DNS name for the network from step 1.
    - ``alternative_names``: Alternative names for the service we represent (X509 SANs).
    - ``contact``: A list of contact addresses, usually e-mail addresses, which must be prefixed with ``mailto:``. These contacts may receive notifications about service changes, e.g. certificate revocation or expiry.
    - ``terms_of_service_agreed``: A Boolean confirming that the operator accepts the terms of service for the CA. RFC8555 requires this to be set explicitly by the operator.
    - ``challenge_type``: Currently only `http-01 <https://letsencrypt.org/docs/challenge-types/>`_ is supported.
    - ``challenge_server_interface``: Name of the interface that the ACME challenge server listens on. For http-01 challenges in production, this interface must be exposed publicly on port 80.

4. CCF nodes periodically check for certificate expiry and trigger renewal when 66% of the validity period has elapsed. The resulting certificates are stored in the ``ccf.gov.service.acme_certificates`` table and upon an update to this table, nodes will automatically install the corresponding certificate on their interfaces. If necessary, renewal can also be triggered manually by submitting a ``trigger_acme_refresh`` governance proposal.