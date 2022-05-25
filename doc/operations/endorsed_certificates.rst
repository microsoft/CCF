Globally endorsed TLS certificates
==================================

CCF provides an ACME client, which enables it to obtain TLS certificates that are endorsed by external certificate authorities (CA). For instance, the Let's Encrypt CA is endorsed by a root certificate that usually comes pre-installed on many current operating systems. CCF handles the creation and renewal of such certificates, but it requires some configuration.

1. Get a globally reachable DNS name for your CCF network, e.g. ``my-ccf.example.com``, which resolves to the address of at least one node in the network. Multiple nodes or a load balancer address are fine too.

2. ACME http-01 challenges require a challenge server to run on port 80 (non-negotiable). To be able to bind to that port, the cchost binary may need to be given special permission, e.g. by running ``sudo setcap CAP_NET_BIND_SERVICE=+eip cchost``.

3. Configure the CCF ACME client by adding the following information to your cchost configuration file on *all* nodes:

  .. code-block:: json

    "acme_client_config": {
        "ca_certs": [ "----- BEGIN CERTIFICATE ..." ],
        "directory_url": "https://...",
        "service_dns_name": "my-ccf.example.com",        
        "contact": ["mailto:john@example.com"],
        "terms_of_service_agreed": true,
        "challenge_type": "http-01",
        "challenge_server_interface": "0.0.0.0:80"
      }

  - ``ca_certs``: CCF will need to establish https connections with the CA, but does not come with root certificates by default and therefore will fail to establish connections. This setting can be populated with multiple such certificates; e.g. for Let's Encrypt this would be their ISRG Root X1 certificate (see https://letsencrypt.org/certificates/) in PEM format.
  - ``directory_url``: This is the main entry point for the ACME protocol. For Let's Encrypt's staging environment, this is https://acme-staging-v02.api.letsencrypt.org/directory (see also https://letsencrypt.org/docs/staging-environment/; minus the ``-staging`` for their production environment).
  - ``service_dns_name``: The DNS name for the network from step 1.
  - ``contact``: A list of contact addresses, usually e-mail addresses, which must be prefixed with ``mailto:``. These contacts may receive notifications about service changes, e.g. certificate revocation or expiry.
  - ``terms_of_service_agreed``: A Boolean confirming that the operator accepts the terms of service for the CA. RFC8555 requires this to be set explicitly by the operator.
  - ``challenge_type``: Currently only ``http-01`` is supported.
  - ``challenge_server_interface``: Interface for the ACME challenge server to listen on. For ``http-01`` challenges, this must run on port 80.

4. Else    
