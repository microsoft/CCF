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

actions.set(
  "set_service_recent_cose_proposals_window_size",
  new Action(
    function (args) {
      checkType(args.proposal_count, "integer", "proposal_count");
      checkBounds(args.proposal_count, 1, 100000, "proposal_count");
    },
    function (args) {
      const service_info = "public:ccf.gov.service.info";
      const rawService = ccf.kv[service_info].get(getSingletonKvKey());
      if (rawService === undefined) {
        throw new Error("Service information could not be found");
      }

      const service = ccf.bufToJsonCompatible(rawService);
      service["recent_cose_proposals_window_size"] = args.proposal_count;
      ccf.kv[service_info].set(
        getSingletonKvKey(),
        ccf.jsonCompatibleToBuf(service)
      );
      return true;
    }
  )
);
