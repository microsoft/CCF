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
        // TODO: Check that member id is a valid entity id
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
          console.log("Member " + args.member_id + " does not exist");
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
        return true; // TODO: Check that args is null?
      },

      function (args) {
        ccf.node.rekeyLedger();
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
]);

function validate(input) {
  let proposal = JSON.parse(input);
  let errors = [];
  let position = 0;
  for (const action of proposal["actions"]) {
    const definition = actions.get(action.name);
    if (definition) {
      if (!definition.validate(action.args)) {
        errors.push(`${action.name} at position ${position} failed validation`);
      }
    } else {
      errors.push(`${action.name}: no such action`);
    }
    position++;
  }
  return { valid: errors.length === 0, description: errors.join(", ") };
}

function resolve(proposal, proposer_id, votes) {
  const actions = JSON.parse(proposal)["actions"];
  if (actions.length === 1) {
    if (actions[0].name === "always_accept_noop") {
      return "Accepted";
    }
    if (actions[0].name === "always_reject_noop") {
      return "Rejected";
    }
    if (
      actions[0].name === "always_accept_with_one_vote" &&
      votes.length === 1 &&
      votes[0].vote === true
    ) {
      return "Accepted";
    }
    if (
      actions[0].name === "always_reject_with_one_vote" &&
      votes.length === 1 &&
      votes[0].vote === false
    ) {
      return "Rejected";
    }
    if (actions[0].name === "always_accept_if_voted_by_operator") {
      for (const vote of votes) {
        const mi = ccf.kv["public:ccf.gov.members.info"].get(
          ccf.strToBuf(vote.member_id)
        );
        if (mi && ccf.bufToJsonCompatible(mi).member_data.is_operator) {
          return "Accepted";
        }
      }
    }
    if (
      actions[0].name === "always_accept_if_proposed_by_operator" ||
      actions[0].name === "remove_user"
    ) {
      const mi = ccf.kv["public:ccf.gov.members.info"].get(
        ccf.strToBuf(proposer_id)
      );
      if (mi && ccf.bufToJsonCompatible(mi).member_data.is_operator) {
        return "Accepted";
      }
    }
    if (
      actions[0].name === "always_accept_with_two_votes" &&
      votes.length === 2 &&
      votes[0].vote === true &&
      votes[1].vote === true
    ) {
      return "Accepted";
    }
    if (
      actions[0].name === "always_reject_with_two_votes" &&
      votes.length === 2 &&
      votes[0].vote === false &&
      votes[1].vote === false
    ) {
      return "Rejected";
    }
    if (
      actions[0].name === "rekey_ledger" ||
      actions[0].name === "set_member_data"
    ) {
      return "Accepted";
    }
  }

  return "Open";
}

function apply(proposal) {
  const proposed_actions = JSON.parse(proposal)["actions"];
  for (const proposed_action of proposed_actions) {
    const definition = actions.get(proposed_action.name);
    definition.apply(proposed_action.args);
  }
}
