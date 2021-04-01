export function validate(input) {
  let proposal = JSON.parse(input);
  let errors = [];
  let position = 0;
  for (const action of proposal["actions"]) {
    const definition = actions.get(action.name);
    if (definition) {
      try {
        definition.validate(action.args);
      } catch (e) {
        errors.push(
          `${action.name} at position ${position} failed validation: ${e}\n${e.stack}`
        );
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
    } else if (actions[0].name === "always_throw_in_apply") {
      return "Accepted";
    } else if (actions[0].name === "always_throw_in_resolve") {
      throw Error("Resolve message");
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
          ccf.strToBuf(vote.member_id)
        );
        if (mi && ccf.bufToJsonCompatible(mi).member_data.is_operator) {
          return "Accepted";
        }
        return "Accepted";
      }
    } else if (actions[0].name === "always_accept_if_proposed_by_operator") {
      const mi = ccf.kv["public:ccf.gov.members.info"].get(
        ccf.strToBuf(proposer_id)
      );
      if (mi && (ccf.bufToJsonCompatible(mi).member_data ?? {}).is_operator) {
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
