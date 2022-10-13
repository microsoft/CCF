function getMemberInfo(memberId) {
  const key = ccf.strToBuf(memberId);
  const value = ccf.kv["public:ccf.gov.members.info"].get(key);
  const info = ccf.bufToJsonCompatible(value);
  return info;
}

// Returns true if the member is a recovery member.
function isRecoveryMember(memberId) {
  const key = ccf.strToBuf(memberId);
  const value =
    ccf.kv["public:ccf.gov.members.encryption_public_keys"].get(key);

  if (value) {
    return true;
  }
  return false;
}

// Defines which of the members are operators.
function isOperator(memberId) {
  // Operators cannot be recovery members.
  if (isRecoveryMember(memberId)) {
    return false;
  }
  const info = getMemberInfo(memberId);
  return info.member_data && info.member_data.is_operator;
}

// Defines which of the members are trusted authorities.
function isTrustedAuthority(memberId) {
  const info = getMemberInfo(memberId);
  return info.member_data && info.member_data.is_trusted_authority;
}

// Defines actions that can be passed with sole trusted authority input.
function canTrustedAuthorityPass(action) {
  // Some actions can always be called by trusted authorities.
  const allowedTrustedAuthorityActions = ["trust_node", "retire_node"];
  if (allowedTrustedAuthorityActions.includes(action.name)) {
    return true;
  }
  // Trusted authorities can add or retire operators.
  if (action.name === "set_member_data" || action.name === "set_member") {
    const memberData = action.args["member_data"];
    if (memberData && memberData.is_operator) {
      return true;
    }
  } else if (action.name === "remove_member") {
    if (isOperator(action.args.member_id)) {
      return true;
    }
  }
  return false;
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
    }
  }

  // If the node is a trusted authority, strictly enforce what proposals it can
  // make
  if (isTrustedAuthority(proposer_id)) {
    return actions.every(canTrustedAuthorityPass) ? "Accepted" : "Rejected";
  }

  // For all other proposals (i.e. the real ones), use member
  // majority
  const memberVoteCount = votes.filter((v) => v.vote).length;

  let activeMemberCount = 0;
  ccf.kv["public:ccf.gov.members.info"].forEach((v, key) => {
    const memberId = ccf.bufToStr(key);
    const info = ccf.bufToJsonCompatible(v);
    if (info.status === "Active" && !isTrustedAuthority(memberId) && !isOperator(memberId)) {
      activeMemberCount++;
    }
  });

  // A majority of members can accept a proposal.
  if (memberVoteCount > Math.floor(activeMemberCount / 2)) {
    return "Accepted";
  }

  return "Open";
}
