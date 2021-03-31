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
          ccf.kv["public:ccf.gov.users.info"].delete(rawUserId);
        } else {
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

        ccf.node.triggerRecoverySharesRefresh();
      }
    ),
  ],
  [
    "trigger_recovery_shares_refresh",
    new Action(
      function (args) {
        return true; // TODO: Check that it is null
      },
      function (args) {
        ccf.node.triggerRecoverySharesRefresh();
        return true;
      }
    ),
  ],
  [
    "set_member",
    new Action(
      function (args) {
        return true; // TODO: Check that cert is well formed, and member data too, if it exists
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
        return true;
      }
    ),
  ],
  [
    "remove_member",
    new Action(
      function (args) {
        return typeof args.member_id === "string"; // Check that args.member_id is well formed
      },
      function (args) {
        const rawMemberId = ccf.strToBuf(args.member_id);
        const rawMemberInfo = ccf.kv["public:ccf.gov.members.info"].get(
          rawMemberId
        );
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
            getUniqueKvKey()
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
          // ledger going forward so rekey ledger, issuing new share to
          // remaining active recovery members
          ccf.node.rekeyLedger();
        }
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
        return typeof args.user_id === "string";
      },
      function (args) {
        const userId = ccf.strToBuf(args.user_id);
        ccf.kv["public:ccf.gov.users.certs"].delete(userId);
        ccf.kv["public:ccf.gov.users.info"].delete(userId);
      }
    ),
  ],
  [
    "set_user_data",
    new Action(
      function (args) {
        return (
          typeof args.user_id === "string" && typeof args.user_data === "object"
        );
      },
      function (args) {
        const userId = ccf.strToBuf(args.user_id);

        const rawUserInfo = ccf.kv["public:ccf.gov.users.info"].get(userId);
        if (rawUserInfo === undefined) {
          return; // Idempotent if proposal deletes user data
        }

        if (args.user_data == null) {
          ccf.kv["public:ccf.gov.users.info"].delete(userId);
        } else {
          ccf.kv["public:ccf.gov.users.info"].set(
            userId,
            ccf.jsonCompatibleToBuf(args.user_data)
          );
        }
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
