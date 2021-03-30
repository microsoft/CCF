export function resolve(proposal, proposerId, votes) {
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
