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
      checkX509CertBundle(args.pem, "pem");
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
