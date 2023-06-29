import * as ccfapp from "@microsoft/ccf-app";

export function checkUserCOSESign1Auth(
  request: ccfapp.Request
): ccfapp.Response {
  if (request.caller === null || request.caller === undefined) {
    return { status: 401 };
  }

  const caller = request.caller;
  if (caller.policy !== "user_cose_sign1") {
    return { status: 401 };
  }

  const id: ccfapp.UserCOSESign1AuthnIdentity = caller;
  return { status: 200, body: id.id };
}
