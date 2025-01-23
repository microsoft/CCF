actions.set(
  "add_virtual_measurement",
  new Action(
    function (args) {
      checkType(args.measurement, "string", "measurement");
    },
    function (args, proposalId) {
      const measurement = ccf.strToBuf(args.measurement);
      const ALLOWED = ccf.jsonCompatibleToBuf("AllowedToJoin");
      ccf.kv["public:ccf.gov.nodes.virtual.measurements"].set(
        measurement,
        ALLOWED
      );

      // Adding a new allowed measurement changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
      invalidateOtherOpenProposals(proposalId);
    }
  )
);

actions.set(
  "remove_virtual_measurement",
  new Action(
    function (args) {
      checkType(args.measurement, "string", "measurement");
    },
    function (args) {
      const measurement = ccf.strToBuf(args.measurement);
      ccf.kv["public:ccf.gov.nodes.virtual.measurements"].delete(measurement);
    }
  )
);

actions.set(
  "add_virtual_host_data",
  new Action(
    function (args) {
      checkType(args.host_data, "string", "host_data");
    },
    function (args, proposalId) {
      ccf.kv["public:ccf.gov.nodes.virtual.host_data"].set(
        ccf.strToBuf(args.host_data),
        getSingletonKvKey()
      );

      // Adding a new allowed host data changes the semantics of any other open proposals, so invalidate them to avoid confusion or malicious vote modification
      invalidateOtherOpenProposals(proposalId);
    }
  )
);

actions.set(
  "remove_virtual_host_data",
  new Action(
    function (args) {
      checkType(args.host_data, "string", "host_data");
    },
    function (args) {
      const hostData = ccf.strToBuf(args.host_data);
      ccf.kv["public:ccf.gov.nodes.virtual.host_data"].delete(hostData);
    }
  )
);
