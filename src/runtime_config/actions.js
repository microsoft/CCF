class Action {
  constructor(validate, apply) {
    this.validate = validate;
    this.apply = apply;
  }
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

function checkX509CertChain(value, field) {
  if (!ccf.isValidX509Chain(value)) {
    throw new Error(
      `${field} must be a valid X509 certificate (chain) in PEM format`
    );
  }
}

const actions = new Map([
  [
    "set_member_data",
    new Action(
      function (args) {
        // Check that member id is a valid entity id?
        checkType(args.member_id, "string", "member_id");
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
    "rekey_ledger",
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
      function (args) {
        // Check that args is null?
      },

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

        if (ccf.kv["ccf.gov.users.certs"].has(raw_user_id)) {
          return; // Idempotent
        }

        ccf.kv["ccf.gov.users.certs"].set(raw_user_id, ccf.strToBuf(args.cert));

        if (args.user_data != null) {
          if (ccf.kv["ccf.gov.users.info"].has(raw_user_id)) {
            throw new Error(`User info for ${user_id} already exists`);
            // Internal error
          }

          ccf.kv["ccf.gov.users.info"].set(
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
    "always_accept_noop",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_reject_noop",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_accept_with_one_vote",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_reject_with_one_vote",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_accept_if_voted_by_operator",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_accept_if_proposed_by_operator",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_accept_with_two_votes",
    new Action(
      function (args) {},
      function (args) {}
    ),
  ],
  [
    "always_reject_with_two_votes",
    new Action(
      function (args) {},
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
    "valid_pem",
    new Action(
      function (args) {
        checkX509CertChain(args.pem, "pem");
      },
      function (args) {}
    ),
  ],
]);
