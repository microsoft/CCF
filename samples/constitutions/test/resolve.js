function getMemberInfo(memberId) {
  return ccf.bufToJsonCompatible(
    ccf.kv["public:ccf.gov.members.info"].get(ccf.strToBuf(memberId))
  );
}

function isRecoveryMember(memberId) {
  return (
    ccf.kv["public:ccf.gov.members.encryption_public_keys"].get(
      ccf.strToBuf(memberId)
    ) ?? false
  );
}

// Defines which of the members are operators.
function isOperator(memberId) {
  // Operators cannot be recovery members.
  if (isRecoveryMember(memberId)) {
    return false;
  }
  return getMemberInfo(memberId).member_data?.is_operator ?? false;
}

// Defines which of the members are operator provisioners.
function isOperatorProvisioner(memberId) {
  return getMemberInfo(memberId).member_data?.is_operator_provisioner ?? false;
}

// Defines actions that can be passed with sole operator provisioner input.
function canOperatorProvisionerPass(action) {
  // Operator provisioners can add or retire operators.
  return (
    {
      set_member: () => action.args["member_data"]?.is_operator ?? false,
      remove_member: () => isOperator(action.args["member_id"]),
    }[action.name]?.() ?? false
  );
}

export function resolve(proposal, proposer_id, votes) {
  const actions = JSON.parse(proposal)["actions"];
  if (actions.length === 1) {
    if (actions[0].name === "always_accept_noop") {
      return "Accepted";
    }
    if (actions[0].name === "set_service_recent_cose_proposals_window_size") {
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
    }
  }

  // If the node is an operator provisioner, strictly enforce what proposals it can
  // make
  if (isOperatorProvisioner(proposer_id)) {
    return actions.every(canOperatorProvisionerPass) ? "Accepted" : "Rejected";
  }

  // For all other proposals (i.e. the real ones), use member
  // majority
  const memberVoteCount = votes.filter((v) => v.vote).length;

  let activeMemberCount = 0;
  ccf.kv["public:ccf.gov.members.info"].forEach((v, key) => {
    const memberId = ccf.bufToStr(key);
    const info = ccf.bufToJsonCompatible(v);
    if (
      info.status === "Active" &&
      !isOperatorProvisioner(memberId) &&
      !isOperator(memberId)
    ) {
      activeMemberCount++;
    }
  });

  // A majority of members can accept a proposal.
  if (memberVoteCount > Math.floor(activeMemberCount / 2)) {
    return "Accepted";
  }

  return "Open";
}
