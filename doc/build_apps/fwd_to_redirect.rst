Migrating from forwarding to redirection
========================================

.. note::
    Forwarding is deprecated and will be removed in CCF 8.0. It remains available
    for compatibility in CCF 7.x. First-party configuration tools enable
    redirections by default. Manually configured RPC interfaces which omit
    ``redirections`` still use legacy forwarding; explicitly specifying
    ``"redirections": {}`` enables the default role-based redirect resolvers.

Redirections
------------

Full use of the redirect behaviour requires changes in both the node configuration (by the operator) and the endpoint definitions (by the application developer). First-party applications explicitly select the appropriate redirect strategy for their endpoints. Other applications should also set ``redirection_strategy`` explicitly rather than relying on defaults. If the endpoint definitions are updated, but then deployed on an instance with no per-node redirection configuration, then no redirects will be returned (and the service will instead rely on the previous forwarding behaviour).

Forwarding is deprecated and will be removed in CCF 8.0, so we recommend that all users update their apps and deployments to use redirections.

.. warning::
    While most HTTP client libraries will allow you to automatically follow redirects, many will also remove ``Authorization`` headers after redirection, to prevent you submitting confidential information to an unintended host. Some will only do this if they believe the redirection has crossed to a fresh domain, while others will do it for all redirections.
    
    If your client is submitting an ``Authorization`` header (eg - a JWT Bearer token) yet receiving ``401 Unauthorized`` responses, it is likely that your HTTP middleware is removing this header on redirect. To correct this you may need to disable automatic redirect following, and instead manually intercept all redirect responses to follow the redirect in your own code, without stripping headers (following some check that the redirection is still to the intended CCF service, eg - to the same origin when ignoring subdomain).

Node configuration
~~~~~~~~~~~~~~~~~~

Redirects are enabled for each RPC interface by adding a ``redirections`` object to the interface's JSON configuration. Interfaces `without` this object will follow use each endpoint's `forwarding` properties, to decide whether each request should be executed locally or forwarded, whereas interfaces `with` this object will use each endpoint's `redirection` properties, to decide whether each request should be executed locally or return a redirect header.

An empty object selects the default resolvers: ``to_primary`` resolves to the
primary and ``to_backup`` resolves to a backup. First-party Python tools emit
redirection configuration by default. Applications must retain the required
``forwarding_required`` bundle field for CCF 7.x compatibility, even when using
explicit ``redirection_strategy`` values.

Example configuration, redirecting directly to the current primary's accessible name:

.. code-block:: json

    {
        "network": {
            "node_to_node_interface": { "bind_address": "127.0.0.1:8081" },
            "rpc_interfaces": {
                "interface_name": {
                    "bind_address": "127.0.0.1:8080",
                    "published_address": "ccf.example.com:12345",
                    "redirections": {
                        "to_primary": {
                            "kind": "NodeByRole",
                            "target": { "role": "primary" }
                        }
                    }
                }
            }
        }
    }

Example configuration, redirecting to a static address (such as a load balancer):

.. code-block:: json

    {
        "network": {
            "node_to_node_interface": { "bind_address": "127.0.0.1:8081" },
            "rpc_interfaces": {
                "interface_name": {
                    "bind_address": "127.0.0.1:8080",
                    "published_address": "ccf.example.com:12345",
                    "redirections": {
                        "to_primary": {
                            "kind": "StaticAddress",
                            "target": {
                                "address": "primary.ccf.example.com"
                            }
                        }
                    }
                }
            }
        }
    }

Endpoint definitions
~~~~~~~~~~~~~~~~~~~~

Similar to the ``forwarding_required`` property which specified each endpoint's forwarding behaviour, we introduce a ``redirection_strategy`` property to control the redirection behaviour. This is set by a method on the endpoint in C++:

.. code-block:: cpp

    make_endpoint(...)
      ...
      .set_redirection_strategy(RedirectionStrategy::None)
      ...
      .install()

And a field on the endpoint in JS's ``app.json``:

.. code-block:: json5

    {
        "endpoints": {
            "/foo/{bar}": {
                "get": {
                    // ...
                    "redirection_strategy": "none",
                    // ...
                }
            }
        }
    }

The default value for both is ``ToPrimary``/``"to_primary"``, meaning that all requests will be redirected. We recommend setting intended values with the following mapping, based on the previous forwarding value, to get similar behaviour in both schemes.

.. list-table::
   :header-rows: 1

   * -
     - ``forwarding_required`` (C++ / JS)
     - ``redirection_strategy`` (C++ / JS)
   * -
     - ``Never`` / ``"never"``
     - ``None`` / ``"none"``
   * - For `read-only` operations
     - ``Sometimes``/ ``"sometimes"``
     - ``None`` / ``"none"``
   * -  For `write` operations
     - ``Sometimes`` / ``"sometimes"``
     - ``ToPrimary`` / ``"to_primary"``
   * -
     - ``Always`` / ``"always"``
     - ``ToPrimary`` / ``"to_primary"``

While ``Never`` and ``Always`` have clear analogs in redirection, the session consistency-preserving ``Sometimes`` value is more complicated. All writes should be redirected to a primary, as attempting to execute them on a backup will result in an error. For reads, you may choose to redirect to retain simple consistency, but to support scaling (by reading on backups), we recommend you choose ``None`` for redirections. Where between-request consistency is a strong requirement, we recommend you enforce it at the application level (eg - ETags, request IDs, etc).

ToBackup
~~~~~~~~

A third ``RedirectionStrategy`` exists named ``ToBackup`` (represented by ``"redirection_strategy": "to_backup"`` in ``app.json``). This is a mirror of the ``ToPrimary`` strategy - if such a request is processed by a node which is currently a primary, that node will produce a HTTP redirect response directing to a backup node. The choice of backup is arbitrary. The redirection address which is inserted can be configured per-node by the operator, in the ``redirections.to_backup`` object.

For example, to redirect directly to a backup by their unique accessible hostname:

.. code-block:: json

    {
        "network": {
            "rpc_interfaces": {
                "interface_name": {
                    "redirections": {
                        "to_backup": {
                            "kind": "NodeByRole",
                            "target": { "role": "backup" }
                        }
                    }
                }
            }
        }
    }

To redirect to a static address (such as a load balancer):

.. code-block:: json

    {
        "network": {
            "rpc_interfaces": {
                "interface_name": {
                    "redirections": {
                        "to_backup": {
                            "kind": "StaticAddress",
                            "target": {
                                "address": "backup.ccf.example.com"
                            }
                        }
                    }
                }
            }
        }
    }
