actions.set(
  "set_service_principal",
  new Action(
    function (args) {
      checkType(args.id, "string", "id");
      checkType(args.data, "object", "data");
    },
    function (args) {
      ccf.kv["public:ccf.gov.service_principals"].set(
        ccf.strToBuf(args.id),
        ccf.jsonCompatibleToBuf(args.data)
      );
    }
  )
);

actions.set(
  "remove_service_principal",
  new Action(
    function (args) {
      checkType(args.id, "string", "id");
    },
    function (args) {
      ccf.kv["public:ccf.gov.service_principals"].delete(
        ccf.strToBuf(args.id)
      );
    }
  )
);
