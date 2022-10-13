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
  // trusted authorities cannot be recovery members.
  if (isRecoveryMember(memberId)) {
    return false;
  }
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

export function resolve(proposal, proposerId, votes) {
  const actions = JSON.parse(proposal)["actions"];

  // If the node is a trusted authority, strictly enforce what proposals it can
  // make
  if (isTrustedAuthority(proposer_id)) {
    return actions.every(canTrustedAuthorityPass) ? "Accepted" : "Rejected";
  }

  // Count member votes.
  const memberVoteCount = votes.filter(
    (v) => v.vote && !isTrustedAuthority(v.member_id) && !isOperator(v.member_id)
  ).length;

  // Count active members, excluding trusted authorities and operators.
  let activeMemberCount = 0;
  ccf.kv["public:ccf.gov.members.info"].forEach((value, key) => {
    const memberId = ccf.bufToStr(key);
    const info = ccf.bufToJsonCompatible(value);
    if (info.status === "Active" && !isTrustedAuthority(memberId) && !isOperator(memberId)) {
      activeMemberCount++;
    }
  });

  // A majority of members can always accept a proposal.
  if (memberVoteCount > Math.floor(activeMemberCount / 2)) {
    return "Accepted";
  }

  return "Open";
}
