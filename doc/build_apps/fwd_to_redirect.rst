Migrating from forwarding to redirection
========================================

.. note::
    Forwarding is removed in CCF 8.0. Applications must use redirection policies, and clients must follow redirects when a request needs to execute on another node.

Redirections
------------

External requests use each endpoint's ``redirection_strategy``, regardless of whether the operator has configured redirect resolvers. The default endpoint strategy redirects requests to the primary. Read-only and node-local endpoints should explicitly use ``None``/``"none"`` where appropriate.

Remove ``forwarding_required`` from JS endpoint metadata and replace C++ ``set_forwarding_required`` calls with ``set_redirection_strategy``. The ``forwarding_timeout_ms`` RPC interface option and ``--forwarding-timeout-ms`` test/deployment argument are also removed.

Before a live upgrade from an older release, explicitly enable ``redirections`` on the older nodes' RPC interfaces and set the application's intended redirection strategies. CCF 8.0 nodes do not accept forwarded node-to-node requests from older peers. Older nodes may still require ``forwarding_required`` in JS bundles, so retain that field until all nodes have been upgraded; CCF 8.0 ignores the legacy field when reading existing endpoint records.

.. warning::
    While most HTTP client libraries will allow you to automatically follow redirects, many will also remove ``Authorization`` headers after redirection, to prevent you submitting confidential information to an unintended host. Some will only do this if they believe the redirection has crossed to a fresh domain, while others will do it for all redirections.
    
    If your client is submitting an ``Authorization`` header (eg - a JWT Bearer token) yet receiving ``401 Unauthorized`` responses, it is likely that your HTTP middleware is removing this header on redirect. To correct this you may need to disable automatic redirect following, and instead manually intercept all redirect responses to follow the redirect in your own code, without stripping headers (following some check that the redirection is still to the intended CCF service, eg - to the same origin when ignoring subdomain).

Node configuration
~~~~~~~~~~~~~~~~~~

The optional ``redirections`` object in each RPC interface's JSON configuration overrides how redirect targets are resolved. When it is omitted, ``to_primary`` resolves the current primary and ``to_backup`` resolves a backup, using the target node's published address for the same interface. Omitted individual resolvers use these same defaults.

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

The ``redirection_strategy`` property controls endpoint redirection behaviour. This is set by a method on the endpoint in C++:

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

The default value for JS endpoints and C++ ``make_endpoint`` is ``ToPrimary``/``"to_primary"``. Requests received by a backup are redirected to the primary. C++ ``make_read_only_endpoint`` and ``make_command_endpoint`` default to ``None``. We recommend setting intended values with the following mapping, based on the previous forwarding value.

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
