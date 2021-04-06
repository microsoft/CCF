export function resolve(proposal, proposerId, votes) {
  // Every member has the ability to veto a proposal.
  // If they vote against it, it is rejected.
  if (votes.some((v) => !v.vote)) {
    return "Rejected";
  }

  const memberVoteCount = votes.length;

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
