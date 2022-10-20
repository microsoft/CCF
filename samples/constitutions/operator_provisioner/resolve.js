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
  return (
    !isRecoveryMember(memberId) &&
    (getMemberInfo(memberId).member_data?.is_operator_provisioner ?? false)
  );
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

export function resolve(proposal, proposerId, votes) {
  const actions = JSON.parse(proposal)["actions"];

  // If the node is an operator provisioner, strictly enforce what proposals it can
  // make
  if (isOperatorProvisioner(proposer_id)) {
    return actions.every(canOperatorProvisionerPass) ? "Accepted" : "Rejected";
  }

  // Count member votes.
  const memberVoteCount = votes.filter(
    (v) =>
      v.vote && !isOperatorProvisioner(v.member_id) && !isOperator(v.member_id)
  ).length;

  // Count active members, excluding operator provisioners and operators.
  let activeMemberCount = 0;
  ccf.kv["public:ccf.gov.members.info"].forEach((value, key) => {
    const memberId = ccf.bufToStr(key);
    const info = ccf.bufToJsonCompatible(value);
    if (
      info.status === "Active" &&
      !isOperatorProvisioner(memberId) &&
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
