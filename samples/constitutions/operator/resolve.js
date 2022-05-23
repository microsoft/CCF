function getMemberInfo(memberId) {
  const key = ccf.strToBuf(memberId);
  const value = ccf.kv["public:ccf.gov.members.info"].get(key);
  const info = ccf.bufToJsonCompatible(value);
  return info;
}

// Returns true if the member is a recovery member.
function isRecoveryMember(memberId) {
  const info = getMemberInfo(memberId);
  if (info.member_data.encryption_pub_key) {
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
  return info.member_data.is_operator;
}

// Defines actions that can be passed with sole operator input.
function canOperatorPass(action) {
  // Some actions can always be called by operators.
  const allowedOperatorActions = ["trust_node", "retire_node", "new_node_code"];
  if (allowedOperatorActions.includes(action.name)) {
    return true;
  }
  // Additionally, operators can add or retire other operators.
  if (action.name === "set_member") {
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

  // Count member votes.
  const memberVoteCount = votes.filter(
    (v) => v.vote && !isOperator(v.member_id)
  ).length;

  // Count active members, excluding operators.
  let activeMemberCount = 0;
  ccf.kv["public:ccf.gov.members.info"].forEach((value, key) => {
    const memberId = ccf.bufToStr(key);
    const info = ccf.bufToJsonCompatible(value);
    if (info.status === "Active" && !isOperator(memberId)) {
      activeMemberCount++;
    }
  });

  // A proposal is an operator change if it's only applying operator actions.
  const isOperatorChange = actions.every(canOperatorPass);

  // A majority of members can always accept a proposal.
  if (memberVoteCount > Math.floor(activeMemberCount / 2)) {
    return "Accepted";
  }

  // Operators proposing operator changes can accept them without a vote.
  if (isOperatorChange && isOperator(proposerId)) {
    return "Accepted";
  }

  return "Open";
}
