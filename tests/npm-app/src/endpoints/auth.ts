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

type Lines = Array<string>;

// Note: This also exists in `logging.js`, but we re-implement here to test the
// additional types in the TypeScript API
export function checkMultiAuth(request: ccfapp.Request): ccfapp.Response {
  var lines: Lines = [];

  if (request.caller.policy === "user_cert") {
    describe_user_cert_ident(lines, request.caller);
  } else if (request.caller.policy === "member_cert") {
    describe_member_cert_ident(lines, request.caller);
  } else if (request.caller.policy === "any_cert") {
    describe_any_cert_ident(lines, request.caller);
  } else if (request.caller.policy === "jwt") {
    describe_jwt_ident(lines, request.caller);
  } else if (request.caller.policy === "user_cose_sign1") {
    describe_user_cose_ident(lines, request.caller);
  } else if (request.caller.policy === "member_cose_sign1") {
    describe_member_cose_ident(lines, request.caller);
  } else if (request.caller.policy === "no_auth") {
    describe_noauth_ident(lines, request.caller);
  } else if (Array.isArray(request.caller.policy)) {
    describe_allofauth_ident(lines, request.caller);
  }

  let s = lines.join("\n");
  console.log(s);
  return { statusCode: 200, body: s };
}

function describe_user_cert_ident(
  lines: Lines,
  obj: ccfapp.UserCertAuthnIdentity,
) {
  lines.push("User TLS cert");
  lines.push(`The caller is a user with ID: ${obj.id}`);
  lines.push(`The caller's user data is: ${JSON.stringify(obj.data, null, 2)}`);
  lines.push(`The caller's cert is:\n${obj.cert}`);
}

function describe_member_cert_ident(
  lines: Lines,
  obj: ccfapp.MemberCertAuthnIdentity,
) {
  lines.push("Member TLS cert");
  lines.push(`The caller is a member with ID: ${obj.id}`);
  lines.push(`The caller's user data is: ${JSON.stringify(obj.data, null, 2)}`);
  lines.push(`The caller's cert is:\n${obj.cert}`);
}

function describe_any_cert_ident(
  lines: Lines,
  obj: ccfapp.AnyCertAuthnIdentity,
) {
  lines.push("Any TLS cert");
  lines.push(`The caller's cert is:\n${obj.cert}`);
}

function describe_jwt_ident(lines: Lines, obj: ccfapp.JwtAuthnIdentity) {
  lines.push("JWT");
  lines.push(
    `The caller is identified by a JWT issued by: ${obj.jwt.keyIssuer}`,
  );
  lines.push(`The JWT header is:\n${JSON.stringify(obj.jwt.header, null, 2)}`);
  lines.push(
    `The JWT payload is:\n${JSON.stringify(obj.jwt.payload, null, 2)}`,
  );
}

function describe_user_cose_ident(
  lines: Lines,
  obj: ccfapp.UserCOSESign1AuthnIdentity,
) {
  lines.push("User COSE Sign1");
  lines.push(
    `The caller is identified by a COSE Sign1 signed by kid: ${obj.id}`,
  );
  lines.push(
    `The caller is identified by a COSE Sign1 with content of size: ${obj.cose.content.byteLength}`,
  );
}

function describe_member_cose_ident(
  lines: Lines,
  obj: ccfapp.MemberCOSESign1AuthnIdentity,
) {
  lines.push("Member COSE Sign1");
  lines.push(
    `The caller is identified by a COSE Sign1 signed by kid: ${obj.id}`,
  );
  lines.push(
    `The caller is identified by a COSE Sign1 with content of size: ${obj.cose.content.byteLength}`,
  );
}

function describe_noauth_ident(lines: Lines, obj: ccfapp.EmptyAuthnIdentity) {
  lines.push("Unauthenticated");
  lines.push("The caller did not provide any authenticated identity");
}

function describe_allofauth_ident(
  lines: Lines,
  obj: ccfapp.AllOfAuthnIdentity,
) {
  lines.push(`Conjoined auth policy: ${obj.policy}`);
  if (obj.policy.includes("user_cert")) {
    lines.push("");
    lines.push("user_cert:");
    describe_user_cert_ident(lines, obj.user_cert);
  }
  if (obj.policy.includes("member_cert")) {
    lines.push("");
    lines.push("member_cert:");
    describe_member_cert_ident(lines, obj.member_cert);
  }
  if (obj.policy.includes("jwt")) {
    lines.push("");
    lines.push("jwt:");
    describe_jwt_ident(lines, obj.jwt);
  }
  if (obj.policy.includes("user_cose_sign1")) {
    lines.push("");
    lines.push("user_cose_sign1:");
    describe_user_cose_ident(lines, obj.user_cose_sign1);
  }
  if (obj.policy.includes("member_cose_sign1")) {
    lines.push("");
    lines.push("member_cose_sign1:");
    describe_member_cose_ident(lines, obj.member_cose_sign1);
  }
}
