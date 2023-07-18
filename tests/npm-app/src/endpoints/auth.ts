import * as ccfapp from "@microsoft/ccf-app";

// Note: this is also tested more generically on the multi_auth endpoint
// of the logging application, but not with TypeScript types.
export function checkUserCOSESign1Auth(
  request: ccfapp.Request,
): ccfapp.Response {
  if (request.caller === null || request.caller === undefined) {
    return { status: 401 };
  }

  const caller = request.caller;
  if (caller.policy !== "user_cose_sign1") {
    return { status: 401 };
  }

  const c: ccfapp.UserCOSESign1AuthnIdentity = caller;
  return { status: 200, body: c};
}
