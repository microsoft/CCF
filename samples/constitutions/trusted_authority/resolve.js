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

// Defines which of the members are trusted authorities.
function isTrustedAuthority(memberId) {
  return getMemberInfo(memberId).member_data?.is_trusted_authority ?? false;
}

// Defines actions that can be passed with sole trusted authority input.
function canTrustedAuthorityPass(action) {
  // Some actions can always be called by trusted authorities.
  const allowedTrustedAuthorityActions = ["trust_node", "retire_node"];
  if (allowedTrustedAuthorityActions.includes(action.name)) {
    return true;
  }
  // Trusted authorities can add or retire operators.
  return (
    {
      set_member_data: () => action.args["member_data"]?.is_operator ?? false,
      set_member: () => action.args["member_data"]?.is_operator ?? false,
      remove_member: () => isOperator(action.args.memberId),
    }[action.name.toString()]() ?? false
  );
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
    (v) =>
      v.vote && !isTrustedAuthority(v.member_id) && !isOperator(v.member_id)
  ).length;

  // Count active members, excluding trusted authorities and operators.
  let activeMemberCount = 0;
  ccf.kv["public:ccf.gov.members.info"].forEach((value, key) => {
    const memberId = ccf.bufToStr(key);
    const info = ccf.bufToJsonCompatible(value);
    if (
      info.status === "Active" &&
      !isTrustedAuthority(memberId) &&
      !isOperator(memberId)
    ) {
      activeMemberCount++;
    }
  });

  // A majority of members can always accept a proposal.
  if (memberVoteCount > Math.floor(activeMemberCount / 2)) {
    return "Accepted";
  }

  return "Open";
}
