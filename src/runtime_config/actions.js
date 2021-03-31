class Action {
  constructor(validate, apply) {
    this.validate = validate;
    this.apply = apply;
  }
}

const actions = new Map([
  [
    "set_member_data",
    new Action(
      function (args) {
        // Check that member id is a valid entity id?
        return (
          typeof args.member_id == "string" &&
          typeof args.member_data == "object"
        );
      },

      function (args) {
        let member_id = ccf.strToBuf(args.member_id);
        let members_info = ccf.kv["public:ccf.gov.members.info"];
        let member_info = members_info.get(member_id);
        if (member_info === undefined) {
          console.log(`Member ${args.member_id} does not exist`);
          return false;
        }
        let mi = ccf.bufToJsonCompatible(member_info);
        mi.member_data = args.member_data;
        members_info.set(member_id, ccf.jsonCompatibleToBuf(mi));
        return true;
      }
    ),
  ],
  [
    "rekey_ledger",
    new Action(
      function (args) {
        return true; // Check that args is null?
      },

      function (args) {
        ccf.node.rekeyLedger();
        return true;
      }
    ),
  ],
  [
    "transition_service_to_open",
    new Action(
      function (args) {
        return true; // Check that args is null?
      },

      function (args) {
        ccf.node.transitionServiceToOpen();
        return true;
      }
    ),
  ],
  [
    "set_user",
    new Action(
      function (args) {
        return true; // Check that args is null?
      },

      function (args) {
        let user_id = ccf.pemToId(args.cert);
        let raw_user_id = ccf.strToBuf(user_id);

        if (ccf.kv["ccf.gov.users.certs"].has(raw_user_id)) {
          console.log(`User cert for ${user_id} already exists`);
          return true; // Idempotent
        }

        ccf.kv["ccf.gov.users.certs"].set(raw_user_id, ccf.strToBuf(args.cert));

        if (args.user_data != null) {
          if (ccf.kv["ccf.gov.users.info"].has(raw_user_id)) {
            console.log(`User info for ${user_id} already exists`);
            return false; // Internal error
          }

          ccf.kv["ccf.gov.users.info"].set(
            raw_user_id,
            ccf.jsonCompatibleToBuf(args.user_data)
          );
        }

        return true;
      }
    ),
  ],
  [
    "set_recovery_threshold",
    new Action(
      function (args) {
        return (
          Number.isInteger(args.threshold) &&
          args.threshold > 0 &&
          args.threshold < 255
        );
      },
      function (args) {}
    ),
  ],
  [
    "always_accept_noop",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_reject_noop",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_accept_with_one_vote",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_reject_with_one_vote",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_accept_if_voted_by_operator",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_accept_if_proposed_by_operator",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_accept_with_two_votes",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "always_reject_with_two_votes",
    new Action(
      function (args) {
        return true;
      },
      function (args) {}
    ),
  ],
  [
    "remove_user",
    new Action(
      function (args) {
        return typeof args.user_id === "string";
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
        return ccf.isValidX509Chain(args.pem);
      },
      function (args) {}
    ),
  ],
  [
    "always_throw_in_apply",
    new Action(
      function (args) {
        return true;
      },
      function (args) {
        throw new Error("Error message");
      }
    ),
  ],
  [
    "always_throw_in_resolve",
    new Action(
      function (args) {
        return true;
      },
      function (args) {
        return true;
      }
    ),
  ],
]);
