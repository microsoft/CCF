import * as ccfapp from "@microsoft/ccf-app";

// Note: this is also tested more generically on the multi_auth endpoint
// of the logging application, but not with TypeScript types.
export function checkUserCOSESign1Auth(
  request: ccfapp.Request,
): ccfapp.Response {
  if (request.caller === null || request.caller === undefined) {
    return { statusCode: 401 };
  }

  const caller = request.caller;
  if (caller.policy !== "user_cose_sign1") {
    return { statusCode: 401 };
  }

  const c: ccfapp.UserCOSESign1AuthnIdentity = caller;
  if (
    request.body.arrayBuffer().byteLength > 0 &&
    c.cose.content.byteLength == 0
  ) {
    return { statusCode: 401 };
  }

  return { statusCode: 200, body: c };
}
