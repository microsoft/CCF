class Action {
  constructor(validate, apply) {
    this.validate = validate;
    this.apply = apply;
  }
}

function parseUrl(url) {
  // From https://tools.ietf.org/html/rfc3986#appendix-B
  const re = new RegExp(
    "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?"
  );
  const groups = url.match(re);
  if (!groups) {
    throw new TypeError(`${url} is not a valid URL.`);
  }
  return {
    scheme: groups[2],
    authority: groups[4],
    path: groups[5],
    query: groups[7],
    fragment: groups[9],
  };
}

function checkType(value, type, field) {
  const optional = type.endsWith("?");
  if (optional) {
    if (value === null || value === undefined) {
      return;
    }
    type = type.slice(0, -1);
  }
  if (type === "array") {
    if (!Array.isArray(value)) {
      throw new Error(`${field} must be an array`);
    }
  } else if (type === "integer") {
    if (!Number.isInteger(value)) {
      throw new Error(`${field} must be an integer`);
    }
  } else if (typeof value !== type) {
    throw new Error(`${field} must be of type ${type} but is ${typeof value}`);
  }
}

function checkEnum(value, members, field) {
  if (!members.includes(value)) {
    throw new Error(`${field} must be one of ${members}`);
  }
}

function checkBounds(value, low, high, field) {
  if (low !== null && value < low) {
    throw new Error(`${field} must be greater than ${low}`);
  }
  if (high !== null && value > high) {
    throw new Error(`${field} must be lower than ${high}`);
  }
}

function checkLength(value, min, max, field) {
  if (min !== null && value.length < min) {
    throw new Error(`${field} must be an array of minimum ${min} elements`);
  }
  if (max !== null && value.length > max) {
    throw new Error(`${field} must be an array of maximum ${max} elements`);
  }
}

function checkJwks(value, field) {
  checkType(value, "object", field);
  checkType(value.keys, "array", `${field}.keys`);
  for (const [i, jwk] of value.keys.entries()) {
    checkType(jwk.kid, "string", `${field}.keys[${i}].kid`);
    checkType(jwk.kty, "string", `${field}.keys[${i}].kty`);
    checkType(jwk.x5c, "array", `${field}.keys[${i}].x5c`);
    checkLength(jwk.x5c, 1, null, `${field}.keys[${i}].x5c`);
    for (const [j, b64der] of jwk.x5c.entries()) {
      checkType(b64der, "string", `${field}.keys[${i}].x5c[${j}]`);
      const pem =
        "-----BEGIN CERTIFICATE-----\n" +
        b64der +
        "\n-----END CERTIFICATE-----";
      checkX509CertChain(pem, `${field}.keys[${i}].x5c[${j}]`);
    }
  }
}

function checkX509CertChain(value, field) {
  if (!ccf.isValidX509Chain(value)) {
    throw new Error(
      `${field} must be a valid X509 certificate (chain) in PEM format`
    );
  }
}

const actions = new Map([
  [
    "trigger_ledger_rekey",
    new Action(
      function (args) {},
      function (args) {
        ccf.node.rekeyLedger();
      }
    ),
  ],
  [
    "transition_service_to_open",
    new Action(
      function (args) {},
      function (args) {
        ccf.node.transitionServiceToOpen();
      }
    ),
  ],
  [
    "set_user",
    new Action(
      function (args) {
        // Check that args is null?
      },

      function (args) {
        let user_id = ccf.pemToId(args.cert);
        let raw_user_id = ccf.strToBuf(user_id);

        if (ccf.kv["public:ccf.gov.users.certs"].has(raw_user_id)) {
          return; // Idempotent
        }

        ccf.kv["public:ccf.gov.users.certs"].set(
          raw_user_id,
          ccf.strToBuf(args.cert)
        );

        if (args.user_data != null) {
          if (ccf.kv["public:ccf.gov.users.info"].has(raw_user_id)) {
            throw new Error(`User info for ${user_id} already exists`);
            // Internal error
          }

          ccf.kv["public:ccf.gov.users.info"].set(
            raw_user_id,
            ccf.jsonCompatibleToBuf(args.user_data)
          );
        }
      }
    ),
  ],
  [
    "set_recovery_threshold",
    new Action(
      function (args) {
        checkType(args.threshold, "integer", "threshold");
        checkBounds(args.threshold, 1, 254, "threshold");
      },
      function (args) {}
    ),
  ],
  [
    "remove_user",
    new Action(
      function (args) {
        checkType(args.user_id, "string", "user_id");
      },
      function (args) {
        const user_id = ccf.strToBuf(args.user_id);
        ccf.kv["public:ccf.gov.users.certs"].delete(user_id);
        ccf.kv["public:ccf.gov.users.info"].delete(user_id);
      }
    ),
  ],
  [
    "set_js_app",
    new Action(
      function (args) {
        const bundle = args.bundle;
        checkType(bundle, "object", "bundle");

        let prefix = "bundle.modules";
        checkType(bundle.modules, "array", prefix);
        for (const [i, module] of bundle.modules.entries()) {
          checkType(module, "object", `${prefix}[${i}]`);
          checkType(module.name, "string", `${prefix}[${i}].name`);
          checkType(module.module, "string", `${prefix}[${i}].module`);
        }

        prefix = "bundle.metadata";
        checkType(bundle.metadata, "object", prefix);
        checkType(bundle.metadata.endpoints, "object", `${prefix}.endpoints`);
        for (const [url, endpoint] of Object.entries(
          bundle.metadata.endpoints
        )) {
          checkType(endpoint, "object", `${prefix}.endpoints["${url}"]`);
          for (const [method, info] of Object.entries(endpoint)) {
            const prefix2 = `${prefix}.endpoints["${url}"]["${method}"]`;
            checkType(info, "object", prefix2);
            checkType(info.js_module, "string", `${prefix2}.js_module`);
            checkType(info.js_function, "string", `${prefix2}.js_function`);
            checkEnum(
              info.mode,
              ["readwrite", "readonly", "historical"],
              `${prefix2}.mode`
            );
            checkEnum(
              info.forwarding_required,
              ["sometimes", "always", "never"],
              `${prefix2}.forwarding_required`
            );
            checkType(info.openapi, "object?", `${prefix2}.openapi`);
            checkType(
              info.openapi_hidden,
              "boolean?",
              `${prefix2}.openapi_hidden`
            );
            checkType(
              info.authn_policies,
              "array",
              `${prefix2}.authn_policies`
            );
            for (const [i, policy] of info.authn_policies.entries()) {
              checkType(policy, "string", `${prefix2}.authn_policies[${i}]`);
            }
            if (!bundle.modules.some((m) => m.name === info.js_module)) {
              throw new Error(`module '${info.js_module}' not found in bundle`);
            }
          }
        }
      },
      function (args) {
        const modulesMap = ccf.kv["public:ccf.gov.modules"];
        const endpointsMap = ccf.kv["public:ccf.gov.endpoints"];
        // kv should expose .clear()
        modulesMap.forEach((_, k) => {
          modulesMap.delete(k);
        });
        endpointsMap.forEach((_, k) => {
          endpointsMap.delete(k);
        });

        const bundle = args.bundle;
        for (const module of bundle.modules) {
          const path = "/" + module.name;
          const pathBuf = ccf.strToBuf(path);
          const moduleBuf = ccf.strToBuf(module.module);
          modulesMap.set(pathBuf, moduleBuf);
        }

        for (const [url, endpoint] of Object.entries(
          bundle.metadata.endpoints
        )) {
          for (const [method, info] of Object.entries(endpoint)) {
            const key = `${method.toUpperCase()} ${url}`;
            const keyBuf = ccf.strToBuf(key);

            info.js_module = "/" + info.js_module;
            const infoBuf = ccf.jsonCompatibleToBuf(info);
            endpointsMap.set(keyBuf, infoBuf);
          }
        }
      }
    ),
  ],
  [
    "remove_js_app",
    new Action(
      function (args) {},
      function (args) {
        const modulesMap = ccf.kv["public:ccf.gov.modules"];
        const endpointsMap = ccf.kv["public:ccf.gov.endpoints"];
        // kv should expose .clear()
        modulesMap.forEach((_, k) => {
          modulesMap.delete(k);
        });
        endpointsMap.forEach((_, k) => {
          endpointsMap.delete(k);
        });
      }
    ),
  ],
  [
    "set_ca_cert_bundle",
    new Action(
      function (args) {
        checkType(args.name, "string", "name");
        checkX509CertChain(args.cert_bundle, "cert_bundle");
      },
      function (args) {
        const name = args.name;
        const bundle = args.cert_bundle;
        const nameBuf = ccf.strToBuf(name);
        const bundleBuf = ccf.jsonCompatibleToBuf(bundle);
        ccf.kv["public:ccf.gov.tls.ca_cert_bundles"].set(nameBuf, bundleBuf);
      }
    ),
  ],
  [
    "remove_ca_cert_bundle",
    new Action(
      function (args) {
        checkType(args, "string", "args");
      },
      function (args) {
        const name = args;
        const nameBuf = ccf.strToBuf(name);
        ccf.kv["public:ccf.gov.tls.ca_cert_bundles"].delete(nameBuf);
      }
    ),
  ],
  [
    "set_jwt_issuer",
    new Action(
      function (args) {
        checkType(args.issuer, "string", "issuer");
        checkType(args.auto_refresh, "boolean?", "auto_refresh");
        checkType(args.ca_cert_bundle_name, "string?", "ca_cert_bundle_name");
        checkEnum(args.key_filter, ["all", "sgx"], "key_filter");
        checkType(args.key_policy, "object?", "key_policy");
        if (args.key_policy) {
          checkType(
            args.key_policy.sgx_claims,
            "object?",
            "key_policy.sgx_claims"
          );
          if (args.key_policy.sgx_claims) {
            for (const [name, value] of Object.entries(
              args.key_policy.sgx_claims
            )) {
              checkType(value, "string", `key_policy.sgx_claims["${name}"]`);
            }
          }
        }
        checkType(args.jwks, "object?", "jwks");
        if (args.jwks) {
          checkJwks(args.jwks, "jwks");
        }
        if (args.auto_refresh) {
          if (!args.ca_cert_bundle_name) {
            throw new Error(
              "ca_cert_bundle_name is missing but required if auto_refresh is true"
            );
          }
          let url;
          try {
            url = parseUrl(args.issuer);
          } catch (e) {
            throw new Error("issuer must be a URL if auto_refresh is true");
          }
          if (url.scheme != "https") {
            throw new Error(
              "issuer must be a URL starting with https:// if auto_refresh is true"
            );
          }
          if (url.query || url.fragment) {
            throw new Error(
              "issuer must be a URL without query/fragment if auto_refresh is true"
            );
          }
        }
      },
      function (args) {
        if (args.auto_refresh) {
          const caCertBundleName = args.ca_cert_bundle_name;
          const caCertBundleNameBuf = ccf.strToBuf(args.ca_cert_bundle_name);
          if (
            !ccf.kv["public:ccf.gov.tls.ca_cert_bundles"].has(
              caCertBundleNameBuf
            )
          ) {
            throw new Error(
              `No CA cert bundle found with name '${caCertBundleName}'`
            );
          }
        }
        const issuer = args.issuer;
        const jwks = args.jwks;
        delete args.jwks;
        const metadata = args;
        if (jwks) {
          ccf.setJwtPublicSigningKeys(issuer, metadata, jwks);
        }
        const issuerBuf = ccf.strToBuf(issuer);
        const metadataBuf = ccf.jsonCompatibleToBuf(metadata);
        ccf.kv["public:ccf.gov.jwt.issuers"].set(issuerBuf, metadataBuf);
      }
    ),
  ],
  [
    "set_jwt_public_signing_keys",
    new Action(
      function (args) {
        checkType(args.issuer, "string", "issuer");
        checkJwks(args.jwks, "jwks");
      },
      function (args) {
        const issuer = args.issuer;
        const issuerBuf = ccf.strToBuf(issuer);
        const metadataBuf = ccf.kv["public:ccf.gov.jwt.issuers"].get(issuerBuf);
        if (metadataBuf === undefined) {
          throw new Error(`issuer ${issuer} not found`);
        }
        const metadata = ccf.bufToJsonCompatible(metadataBuf);
        const jwks = args.jwks;
        ccf.setJwtPublicSigningKeys(issuer, metadata, jwks);
      }
    ),
  ],
  [
    "remove_jwt_issuer",
    new Action(
      function (args) {
        checkType(args.issuer, "string", "issuer");
      },
      function (args) {
        const issuerBuf = ccf.strToBuf(args.issuer);
        if (!ccf.kv["public:ccf.gov.jwt.issuers"].delete(issuerBuf)) {
          return;
        }
        ccf.removeJwtPublicSigningKeys(args.issuer);
      }
    ),
  ],
  [
    "transition_node_to_trusted",
    new Action(
      function (args) {
        checkType(args.node_id, "string", "node_id");
      },
      function (args) {
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id)
        );
        if (node === undefined) {
          throw new Error(`No such node: ${args.node_id}`);
        }
        const nodeInfo = ccf.bufToJsonCompatible(node);
        if (nodeInfo.status === "Pending") {
          nodeInfo.status = "Trusted";
          nodeInfo.ledger_secret_seqno = ccf.network.getLatestLedgerSecretSeqno();
          ccf.kv["public:ccf.gov.nodes.info"].set(
            ccf.strToBuf(args.node_id),
            ccf.jsonCompatibleToBuf(nodeInfo)
          );
        }
      }
    ),
  ],
  [
    "remove_node",
    new Action(
      function (args) {
        checkType(args.node_id, "string", "node_id");
      },
      function (args) {
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id)
        );
        if (node !== undefined) {
          const node_obj = ccf.bufToJsonCompatible(node);
          node_obj.status = "Retired";
          ccf.kv["public:ccf.gov.nodes.info"].set(
            ccf.strToBuf(args.node_id),
            ccf.jsonCompatibleToBuf(node_obj)
          );
        }
      }
    ),
  ],
]);
