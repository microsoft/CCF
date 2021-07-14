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

function checkNone(args) {
  if (args !== null && args !== undefined) {
    throw new Error(`Proposal does not accept any argument, found "${args}"`);
  }
}

function checkEntityId(value, field) {
  checkType(value, "string", field);
  // This should be the hex-encoding of a SHA256 digest. This is 32 bytes long, so
  // produces 64 hex characters.
  const digestLength = 64;
  if (value.length !== digestLength) {
    throw new Error(`${field} must contain exactly ${digestLength} characters`);
  }
  const re = new RegExp("^[a-fA-F0-9]*$");
  if (!re.test(value)) {
    throw new Error(`${field} contains non-hexadecimal character`);
  }
}

function getSingletonKvKey() {
  // When a KV map only contains one value, this is the key at which
  // the value is recorded
  return new ArrayBuffer(8);
}

function getActiveRecoveryMembersCount() {
  let activeRecoveryMembersCount = 0;
  ccf.kv["public:ccf.gov.members.encryption_public_keys"].forEach((_, k) => {
    let rawMemberInfo = ccf.kv["public:ccf.gov.members.info"].get(k);
    if (rawMemberInfo === undefined) {
      throw new Error(`Recovery member ${ccf.bufToStr(k)} has no information`);
    }

    const memberInfo = ccf.bufToJsonCompatible(rawMemberInfo);
    if (memberInfo.status === "Active") {
      activeRecoveryMembersCount++;
    }
  });
  return activeRecoveryMembersCount;
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
      checkX509CertBundle(pem, `${field}.keys[${i}].x5c[${j}]`);
    }
  }
}

function checkX509CertBundle(value, field) {
  if (!ccf.isValidX509CertBundle(value)) {
    throw new Error(
      `${field} must be a valid X509 certificate (bundle) in PEM format`
    );
  }
}

function invalidateOtherOpenProposals(proposalIdToRetain) {
  let proposals = ccf.kv["public:ccf.gov.proposals_info"];
  const proposalsMap = ccf.kv["public:ccf.gov.proposals_info"];
  proposalsMap.forEach((v, k) => {
    let proposalId = ccf.bufToStr(k);
    if (proposalId !== proposalIdToRetain) {
      let info = ccf.bufToJsonCompatible(v);
      if (info.state === "Open") {
        info.state = "Dropped";
        proposalsMap.set(k, ccf.jsonCompatibleToBuf(info));
      }
    }
  });
}

const actions = new Map([
  [
    "set_constitution",
    new Action(
      function (args) {
        checkType(args.constitution, "string");
      },
      function (args, proposalId) {
        ccf.kv["public:ccf.gov.constitution"].set(
          getSingletonKvKey(),
          ccf.jsonCompatibleToBuf(args.constitution)
        );

        // Changing the constitution changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
        invalidateOtherOpenProposals(proposalId);
      }
    ),
  ],
  [
    "set_member",
    new Action(
      function (args) {
        checkX509CertBundle(args.cert, "cert");
        checkType(args.member_data, "object?", "member_data");
        // Also check that public encryption key is well formed, if it exists
      },

      function (args) {
        const memberId = ccf.pemToId(args.cert);
        const rawMemberId = ccf.strToBuf(memberId);

        ccf.kv["public:ccf.gov.members.certs"].set(
          rawMemberId,
          ccf.strToBuf(args.cert)
        );

        if (args.encryption_pub_key == null) {
          ccf.kv["public:ccf.gov.members.encryption_public_keys"].delete(
            rawMemberId
          );
        } else {
          ccf.kv["public:ccf.gov.members.encryption_public_keys"].set(
            rawMemberId,
            ccf.strToBuf(args.encryption_pub_key)
          );
        }

        let member_info = {};
        member_info.member_data = args.member_data;
        member_info.status = "Accepted";
        ccf.kv["public:ccf.gov.members.info"].set(
          rawMemberId,
          ccf.jsonCompatibleToBuf(member_info)
        );

        const rawSignature = ccf.kv["public:ccf.internal.signatures"].get(
          getSingletonKvKey()
        );
        if (rawSignature === undefined) {
          ccf.kv["public:ccf.gov.members.acks"].set(rawMemberId);
        } else {
          const signature = ccf.bufToJsonCompatible(rawSignature);
          const ack = {};
          ack.state_digest = signature.root;
          ccf.kv["public:ccf.gov.members.acks"].set(
            rawMemberId,
            ccf.jsonCompatibleToBuf(ack)
          );
        }
      }
    ),
  ],
  [
    "remove_member",
    new Action(
      function (args) {
        checkEntityId(args.member_id, "member_id");
      },
      function (args) {
        const rawMemberId = ccf.strToBuf(args.member_id);
        const rawMemberInfo =
          ccf.kv["public:ccf.gov.members.info"].get(rawMemberId);
        if (rawMemberInfo === undefined) {
          return; // Idempotent
        }

        const memberInfo = ccf.bufToJsonCompatible(rawMemberInfo);
        const isActiveMember = memberInfo.status == "Active";

        const isRecoveryMember = ccf.kv[
          "public:ccf.gov.members.encryption_public_keys"
        ].has(rawMemberId)
          ? true
          : false;

        // If the member is an active recovery member, check that there
        // would still be a sufficient number of recovery members left
        // to recover the service
        if (isActiveMember && isRecoveryMember) {
          const rawConfig = ccf.kv["public:ccf.gov.service.config"].get(
            getSingletonKvKey()
          );
          if (rawConfig === undefined) {
            throw new Error("Service configuration could not be found");
          }

          const config = ccf.bufToJsonCompatible(rawConfig);
          const activeRecoveryMembersCountAfter =
            getActiveRecoveryMembersCount() - 1;
          if (activeRecoveryMembersCountAfter < config.recovery_threshold) {
            throw new Error(
              `Number of active recovery members (${activeRecoveryMembersCountAfter}) would be less than recovery threshold (${config.recovery_threshold})`
            );
          }
        }

        ccf.kv["public:ccf.gov.members.info"].delete(rawMemberId);
        ccf.kv["public:ccf.gov.members.encryption_public_keys"].delete(
          rawMemberId
        );
        ccf.kv["public:ccf.gov.members.certs"].delete(rawMemberId);
        ccf.kv["public:ccf.gov.members.acks"].delete(rawMemberId);
        ccf.kv["public:ccf.gov.history"].delete(rawMemberId);

        if (isActiveMember && isRecoveryMember) {
          // A retired recovery member should not have access to the private
          // ledger going forward so rekey the ledger, issuing new shares to
          // remaining active recovery members
          ccf.node.triggerLedgerRekey();
        }
      }
    ),
  ],
  [
    "set_member_data",
    new Action(
      function (args) {
        checkEntityId(args.member_id, "member_id");
        checkType(args.member_data, "object", "member_data");
      },

      function (args) {
        let member_id = ccf.strToBuf(args.member_id);
        let members_info = ccf.kv["public:ccf.gov.members.info"];
        let member_info = members_info.get(member_id);
        if (member_info === undefined) {
          throw new Error(`Member ${args.member_id} does not exist`);
        }
        let mi = ccf.bufToJsonCompatible(member_info);
        mi.member_data = args.member_data;
        members_info.set(member_id, ccf.jsonCompatibleToBuf(mi));
      }
    ),
  ],
  [
    "set_user",
    new Action(
      function (args) {
        checkX509CertBundle(args.cert, "cert");
        checkType(args.user_data, "object?", "user_data");
      },
      function (args) {
        let userId = ccf.pemToId(args.cert);
        let rawUserId = ccf.strToBuf(userId);

        ccf.kv["public:ccf.gov.users.certs"].set(
          rawUserId,
          ccf.strToBuf(args.cert)
        );

        if (args.user_data !== null && args.user_data !== undefined) {
          ccf.kv["public:ccf.gov.users.info"].set(
            rawUserId,
            ccf.jsonCompatibleToBuf(args.user_data)
          );
        } else {
          ccf.kv["public:ccf.gov.users.info"].delete(rawUserId);
        }
      }
    ),
  ],
  [
    "remove_user",
    new Action(
      function (args) {
        checkEntityId(args.user_id, "user_id");
      },
      function (args) {
        const user_id = ccf.strToBuf(args.user_id);
        ccf.kv["public:ccf.gov.users.certs"].delete(user_id);
        ccf.kv["public:ccf.gov.users.info"].delete(user_id);
      }
    ),
  ],
  [
    "set_user_data",
    new Action(
      function (args) {
        checkEntityId(args.user_id, "user_id");
        checkType(args.user_data, "object?", "user_data");
      },
      function (args) {
        const userId = ccf.strToBuf(args.user_id);

        if (args.user_data !== null && args.user_data !== undefined) {
          let userInfo = {};
          userInfo.user_data = args.user_data;
          ccf.kv["public:ccf.gov.users.info"].set(
            userId,
            ccf.jsonCompatibleToBuf(userInfo)
          );
        } else {
          ccf.kv["public:ccf.gov.users.info"].delete(userId);
        }
      }
    ),
  ],
  [
    "set_recovery_threshold",
    new Action(
      function (args) {
        checkType(args.recovery_threshold, "integer", "threshold");
        checkBounds(args.recovery_threshold, 1, 254, "threshold");
      },
      function (args) {
        const rawConfig = ccf.kv["public:ccf.gov.service.config"].get(
          getSingletonKvKey()
        );
        if (rawConfig === undefined) {
          throw new Error("Service configuration could not be found");
        }

        let config = ccf.bufToJsonCompatible(rawConfig);

        if (args.recovery_threshold === config.recovery_threshold) {
          return; // No effect
        }

        const rawService = ccf.kv["public:ccf.gov.service.info"].get(
          getSingletonKvKey()
        );
        if (rawService === undefined) {
          throw new Error("Service information could not be found");
        }

        const service = ccf.bufToJsonCompatible(rawService);

        if (service.status === "WaitingForRecoveryShares") {
          throw new Error(
            `Cannot set recovery threshold if service is ${service.status}`
          );
        } else if (service.status === "Open") {
          let activeRecoveryMembersCount = getActiveRecoveryMembersCount();
          if (args.recovery_threshold > activeRecoveryMembersCount) {
            throw new Error(
              `Cannot set recovery threshold to ${args.recovery_threshold}: recovery threshold would be greater than the number of recovery members ${activeRecoveryMembersCount}`
            );
          }
        }

        config.recovery_threshold = args.recovery_threshold;
        ccf.kv["public:ccf.gov.service.config"].set(
          getSingletonKvKey(),
          ccf.jsonCompatibleToBuf(config)
        );

        ccf.node.triggerRecoverySharesRefresh();
      }
    ),
  ],
  [
    "trigger_recovery_shares_refresh",
    new Action(
      function (args) {
        checkNone(args);
      },
      function (args) {
        ccf.node.triggerRecoverySharesRefresh();
      }
    ),
  ],
  [
    "trigger_ledger_rekey",
    new Action(
      function (args) {
        checkNone(args);
      },

      function (args) {
        ccf.node.triggerLedgerRekey();
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

        checkType(
          args.disable_bytecode_cache,
          "boolean?",
          "disable_bytecode_cache"
        );
      },
      function (args) {
        const modulesMap = ccf.kv["public:ccf.gov.modules"];
        const modulesQuickJsBytecodeMap =
          ccf.kv["public:ccf.gov.modules_quickjs_bytecode"];
        const modulesQuickJsVersionVal =
          ccf.kv["public:ccf.gov.modules_quickjs_version"];
        const endpointsMap = ccf.kv["public:ccf.gov.endpoints"];
        modulesMap.clear();
        endpointsMap.clear();

        const bundle = args.bundle;
        for (const module of bundle.modules) {
          const path = "/" + module.name;
          const pathBuf = ccf.strToBuf(path);
          const moduleBuf = ccf.strToBuf(module.module);
          modulesMap.set(pathBuf, moduleBuf);
        }

        if (args.disable_bytecode_cache) {
          modulesQuickJsBytecodeMap.clear();
          modulesQuickJsVersionVal.clear();
        } else {
          ccf.refreshAppBytecodeCache();
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
        const modulesQuickJsBytecodeMap =
          ccf.kv["public:ccf.gov.modules_quickjs_bytecode"];
        const modulesQuickJsVersionVal =
          ccf.kv["public:ccf.gov.modules_quickjs_version"];
        const endpointsMap = ccf.kv["public:ccf.gov.endpoints"];
        modulesMap.clear();
        modulesQuickJsBytecodeMap.clear();
        modulesQuickJsVersionVal.clear();
        endpointsMap.clear();
      }
    ),
  ],
  [
    "refresh_js_app_bytecode_cache",
    new Action(
      function (args) {},
      function (args) {
        ccf.refreshAppBytecodeCache();
      }
    ),
  ],
  [
    "set_ca_cert_bundle",
    new Action(
      function (args) {
        checkType(args.name, "string", "name");
        checkX509CertBundle(args.cert_bundle, "cert_bundle");
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
        checkType(args.name, "string", "name");
      },
      function (args) {
        const name = args.name;
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
    "add_node_code",
    new Action(
      function (args) {
        checkType(args.code_id, "string", "code_id");
      },
      function (args, proposalId) {
        const codeId = ccf.strToBuf(args.code_id);
        const ALLOWED = ccf.jsonCompatibleToBuf("AllowedToJoin");
        ccf.kv["public:ccf.gov.nodes.code_ids"].set(codeId, ALLOWED);

        // Adding a new allowed code ID changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
        invalidateOtherOpenProposals(proposalId);
      }
    ),
  ],

  [
    "transition_node_to_trusted",
    new Action(
      function (args) {
        checkEntityId(args.node_id, "node_id");
      },
      function (args) {
        const rawConfig = ccf.kv["public:ccf.gov.service.config"].get(
          getSingletonKvKey()
        );
        if (rawConfig === undefined) {
          throw new Error("Service configuration could not be found");
        }
        const serviceConfig = ccf.bufToJsonCompatible(rawConfig);
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id)
        );
        if (node === undefined) {
          throw new Error(`No such node: ${args.node_id}`);
        }
        const nodeInfo = ccf.bufToJsonCompatible(node);
        if (nodeInfo.status === "Pending") {
          nodeInfo.status =
            serviceConfig.reconfiguration_type == "TwoTransaction"
              ? "Learner"
              : "Trusted";
          nodeInfo.ledger_secret_seqno =
            ccf.network.getLatestLedgerSecretSeqno();
          ccf.kv["public:ccf.gov.nodes.info"].set(
            ccf.strToBuf(args.node_id),
            ccf.jsonCompatibleToBuf(nodeInfo)
          );
        }
      }
    ),
  ],
  [
    "remove_node_code",
    new Action(
      function (args) {
        checkType(args.code_id, "string", "code_id");
      },
      function (args) {
        const codeId = ccf.strToBuf(args.code_id);
        ccf.kv["public:ccf.gov.nodes.code_ids"].delete(codeId);
      }
    ),
  ],
  [
    "remove_node",
    new Action(
      function (args) {
        checkEntityId(args.node_id, "node_id");
      },
      function (args) {
        const rawConfig = ccf.kv["public:ccf.gov.service.config"].get(
          getSingletonKvKey()
        );
        if (rawConfig === undefined) {
          throw new Error("Service configuration could not be found");
        }
        const serviceConfig = ccf.bufToJsonCompatible(rawConfig);
        const node = ccf.kv["public:ccf.gov.nodes.info"].get(
          ccf.strToBuf(args.node_id)
        );
        if (node !== undefined) {
          const node_obj = ccf.bufToJsonCompatible(node);
          node_obj.status =
            serviceConfig.reconfiguration_type == "TwoTransaction"
              ? "Retiring"
              : "Retired";
          ccf.kv["public:ccf.gov.nodes.info"].set(
            ccf.strToBuf(args.node_id),
            ccf.jsonCompatibleToBuf(node_obj)
          );
        }
      }
    ),
  ],
]);
