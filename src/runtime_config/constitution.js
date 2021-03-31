class Action {
  constructor(validate, apply) {
    this.validate = validate;
    this.apply = apply;
  }
}

function getUniqueKvKey() {
  // When a KV map only contains one value, this is the key at which
  // the value is recorded
  return new ArrayBuffer(8);
}

function getActiveRecoveryMembersCount() {
  let activeRecoveryMembersCount = 0;
  ccf.kv["public:ccf.gov.members.encryption_public_keys"].forEach((_, k) => {
    let member_info = ccf.kv["public:ccf.gov.members.info"].get(k);
    if (member_info === undefined) {
      throw new Error(
        `Recovery member ${ccf.bufToJsonCompatible(k)} has no information`
      );
    }

    const info = ccf.bufToJsonCompatible(member_info);
    if (info.status === "Active") {
      activeRecoveryMembersCount++;
    }
  });
  return activeRecoveryMembersCount;
}

const actions = new Map([
  [
    "set_member_data",
    new Action(
      function (args) {
        return (
          typeof args.member_id == "string" &&
          typeof args.member_data == "object"
        );
      },

      function (args) {
        let memberId = ccf.strToBuf(args.member_id);
        let membersInfo = ccf.kv["public:ccf.gov.members.info"];
        let memberInfo = membersInfo.get(memberId);
        if (memberInfo === undefined) {
          throw new Error(`Member ${args.member_id} does not exist`);
        }
        let mi = ccf.bufToJsonCompatible(memberInfo);
        mi.member_data = args.member_data;
        membersInfo.set(memberId, ccf.jsonCompatibleToBuf(mi));
      }
    ),
  ],
  [
    "rekey_ledger",
    new Action(
      function (args) {
        // Check that args is null?
        return true;
      },

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
        return true;
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
        return true;
      },

      function (args) {
        let userId = ccf.pemToId(args.cert);
        let rawUserId = ccf.strToBuf(userId);

        ccf.kv["public:ccf.gov.users.certs"].set(
          rawUserId,
          ccf.strToBuf(args.cert)
        );

        if (args.user_data == null) {
          console.log("Delete");
          ccf.kv["public:ccf.gov.users.info"].delete(rawUserId);
        } else {
          console.log("Add");
          console.log(typeof args.user_data);
          ccf.kv["public:ccf.gov.users.info"].set(
            rawUserId,
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
        return (
          Number.isInteger(args.recovery_threshold) &&
          args.recovery_threshold > 0 &&
          args.recovery_threshold < 255
        );
      },
      function (args) {
        const rawConfig = ccf.kv["public:ccf.gov.service.config"].get(
          getUniqueKvKey()
        );
        if (rawConfig === undefined) {
          throw new Error("Service configuration could not be found");
        }

        let config = ccf.bufToJsonCompatible(rawConfig);

        if (args.recovery_threshold === config.recovery_threshold) {
          return; // No effect
        }

        const rawService = ccf.kv["public:ccf.gov.service.info"].get(
          getUniqueKvKey()
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
          getUniqueKvKey(),
          ccf.jsonCompatibleToBuf(config)
        );
      }
    ),
  ],
  [
    "trigger_recovery_shares_refresh",
    new Action(
      function (args) {
        return true;
      },
      function (args) {
        ccf.node.triggerRecoverySharesRefresh();
        return true;
      }
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
        return typeof args.userId === "string";
      },
      function (args) {
        const userId = ccf.strToBuf(args.userId);
        ccf.kv["public:ccf.gov.users.certs"].delete(userId);
        ccf.kv["public:ccf.gov.users.info"].delete(userId);
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
]);

export function validate(input) {
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

export function resolve(proposal, proposer_id, votes) {
  const actions = JSON.parse(proposal)["actions"];
  if (actions.length === 1) {
    if (actions[0].name === "always_accept_noop") {
      return "Accepted";
    } else if (actions[0].name === "always_reject_noop") {
      return "Rejected";
    } else if (
      actions[0].name === "always_accept_with_one_vote" &&
      votes.length === 1 &&
      votes[0].vote === true
    ) {
      return "Accepted";
    } else if (
      actions[0].name === "always_reject_with_one_vote" &&
      votes.length === 1 &&
      votes[0].vote === false
    ) {
      return "Rejected";
    } else if (actions[0].name === "always_accept_if_voted_by_operator") {
      for (const vote of votes) {
        const mi = ccf.kv["public:ccf.gov.members.info"].get(
          ccf.strToBuf(vote.memberId)
        );
        if (mi && ccf.bufToJsonCompatible(mi).member_data.is_operator) {
          return "Accepted";
        }
      }
    } else if (
      actions[0].name === "always_accept_if_proposed_by_operator" ||
      actions[0].name === "remove_user"
    ) {
      const mi = ccf.kv["public:ccf.gov.members.info"].get(
        ccf.strToBuf(proposer_id)
      );
      if (mi && ccf.bufToJsonCompatible(mi).member_data.is_operator) {
        return "Accepted";
      }
    } else if (
      actions[0].name === "always_accept_with_two_votes" &&
      votes.length === 2 &&
      votes[0].vote === true &&
      votes[1].vote === true
    ) {
      return "Accepted";
    } else if (
      actions[0].name === "always_reject_with_two_votes" &&
      votes.length === 2 &&
      votes[0].vote === false &&
      votes[1].vote === false
    ) {
      return "Rejected";
    } else {
      // For all other proposals (i.e. the real ones), use member
      // majority
      const memberVoteCount = votes.filter((v) => v.vote).length;

      let activeMemberCount = 0;
      ccf.kv["public:ccf.gov.members.info"].forEach((v) => {
        const info = ccf.bufToJsonCompatible(v);
        if (info.status === "Active") {
          activeMemberCount++;
        }
      });

      console.log("Active members: " + activeMemberCount);
      console.log("Threshold: " + Math.floor(activeMemberCount / 2));
      console.log("Votes: " + memberVoteCount);
      console.log("Votes length: " + votes.length);

      // A majority of members can accept a proposal.
      if (memberVoteCount > Math.floor(activeMemberCount / 2)) {
        return "Accepted";
      }

      return "Open";
    }
  }

  return "Open";
}

export function apply(proposal) {
  const proposed_actions = JSON.parse(proposal)["actions"];
  for (const proposed_action of proposed_actions) {
    const definition = actions.get(proposed_action.name);
    definition.apply(proposed_action.args);
  }
}
