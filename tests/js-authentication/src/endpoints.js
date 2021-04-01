export function jwt(request) {
  console.log("JWT payload is:");
  console.log(JSON.stringify(request.caller.jwt.payload));
  return { body: request.caller.jwt };
}

export function multi_auth(request) {
  var lines = [];

  if (request.caller.policy === "user_cert") {
    lines.push("User TLS cert");
    lines.push(`The caller is a user with ID: ${request.caller.id}`);
    lines.push(
      `The caller's user data is: ${JSON.stringify(request.caller.data)}`
    );
    lines.push(`The caller's cert is:\n${request.caller.cert}`);
  } else if (request.caller.policy === "user_signature") {
    lines.push("User HTTP signature");
    lines.push(`The caller is a user with ID: ${request.caller.id}`);
    lines.push(
      `The caller's user data is: ${JSON.stringify(request.caller.data)}`
    );
    lines.push(`The caller's cert is:\n${request.caller.cert}`);
  } else if (request.caller.policy === "member_cert") {
    lines.push("Member TLS cert");
    lines.push(`The caller is a member with ID: ${request.caller.id}`);
    lines.push(
      `The caller's user data is: ${JSON.stringify(request.caller.data)}`
    );
    lines.push(`The caller's cert is:\n${request.caller.cert}`);
  } else if (request.caller.policy === "member_signature") {
    lines.push("Member HTTP signature");
    lines.push(`The caller is a member with ID: ${request.caller.id}`);
    lines.push(
      `The caller's user data is: ${JSON.stringify(request.caller.data)}`
    );
    lines.push(`The caller's cert is:\n${request.caller.cert}`);
  } else if (request.caller.policy === "jwt") {
    lines.push("JWT");
    lines.push(
      `The caller is identified by a JWT issued by: ${request.caller.jwt.keyIssuer}`
    );
    lines.push(
      `The JWT header is:\n${JSON.stringify(request.caller.jwt.header)}`
    );
    lines.push(
      `The JWT payload is:\n${JSON.stringify(request.caller.jwt.payload)}`
    );
  } else if (request.caller.policy === "no_auth") {
    lines.push("Unauthenticated");
    lines.push("The caller did not provide any authenticated identity");
  }

  let s = lines.join("\n");
  console.log(s);
  return { body: s };
}
