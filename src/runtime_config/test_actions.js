actions.set(
  "set_member_data",
  new Action(
    function (args) {
      // Check that member id is a valid entity id?
      checkType(args.member_id, "string", "member_id");
      checkType(args.member_data, "object", "member_data");
    },

    function (args) {
      let member_id = ccf.strToBuf(args.member_id);
      let members_info = ccf.kv["public:ccf.gov.members.info"];
      let member_info = members_info.get(member_id);
      if (member_info === undefined) {
        throw new Error(`Member ${args.member_id} does not exist`);
      }
      let mi = ccf.bufToJsonCompatible(member_info);
      mi.member_data = args.member_data;
      members_info.set(member_id, ccf.jsonCompatibleToBuf(mi));
    }
  )
);

actions.set(
  "always_accept_noop",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_reject_noop",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_accept_with_one_vote",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_reject_with_one_vote",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_accept_if_voted_by_operator",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_accept_if_proposed_by_operator",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_accept_with_two_votes",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "always_reject_with_two_votes",
  new Action(
    function (args) {},
    function (args) {}
  )
);

actions.set(
  "valid_pem",
  new Action(
    function (args) {
      checkX509CertChain(args.pem, "pem");
    },
    function (args) {}
  )
);

actions.set(
  "always_throw_in_apply",
  new Action(
    function (args) {
      return true;
    },
    function (args) {
      throw new Error("Error message");
    }
  )
);

actions.set(
  "always_throw_in_resolve",
  new Action(
    function (args) {
      return true;
    },
    function (args) {
      return true;
    }
  )
);
