export function cert(request) {
  console.log("Caller cert is:");
  console.log(JSON.stringify(request.caller.cert));
  return { body: request.caller.cert };
}

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

// There's only a single secret, stored at this special key (the empty array)
const key_of_single_secret = new ArrayBuffer();

const roles_table = "my.tables.role";
const secret_table = "my.tables.secret";

function has_role(role, caller) {
  // First, check for a role in the user data, which is only writeable by member governance
  try {
    if (caller.data.role === role) {
      console.log("Found role from governance table");
      return true;
    }
  } catch (err) {
    console.log("User data is not an object");
  }

  // If that didn't succeed, check the app-written entries
  let raw_id = ccf.strToBuf(caller.id);
  let raw_caller_roles = ccf.kv[roles_table].get(raw_id);

  if (raw_caller_roles === undefined) {
    // Caller has no roles in the user-defined table
    return false;
  }

  let caller_roles = ccf.bufToJsonCompatible(raw_caller_roles);

  // caller_roles is a list, check if it contains the requested role
  if (caller_roles.indexOf(role) > -1) {
    console.log("Found role from app table");
    return true;
  }

  return false;
}

function is_secret_reader(caller) {
  return has_role("secret_reader", caller);
}

function is_secret_writer(caller) {
  return has_role("secret_writer", caller);
}

function is_role_master(caller) {
  return has_role("role_master", caller);
}

export function get_secret(request) {
  console.log("Somebody is trying to read the secret");

  if (!is_secret_reader(request.caller)) {
    console.log("They're not allowed to!");
    return {
      statusCode: 401,
      body: { error: "Caller is not permitted to read the secret" },
    };
  }

  const raw_secret = ccf.kv[secret_table].get(key_of_single_secret);
  let result = "No secret has been set";
  if (raw_secret !== undefined) {
    result = ccf.bufToJsonCompatible(raw_secret);
  }

  return {
    body: result,
  };
}

export function put_secret(request) {
  if (!is_secret_writer(request.caller)) {
    return {
      statusCode: 401,
      body: { error: "Caller is not permitted to write the secret" },
    };
  }

  const body = request.body.json();
  ccf.kv[secret_table].set(
    key_of_single_secret,
    ccf.jsonCompatibleToBuf(body.new_secret)
  );

  return {
    statusCode: 204,
  };
}

export function add_role(request) {
  if (!is_role_master(request.caller)) {
    return {
      statusCode: 401,
      body: { error: "Caller is not permitted to modify roles" },
    };
  }

  const body = request.body.json();
  const raw_target_id = ccf.strToBuf(body.target_id);

  let raw_caller_roles = ccf.kv[roles_table].get(raw_target_id);

  let caller_roles = [];
  if (raw_caller_roles !== undefined) {
    caller_roles = ccf.bufToJsonCompatible(raw_caller_roles);
  }

  const target_role = body.target_role;
  caller_roles.push(target_role);

  raw_caller_roles = ccf.jsonCompatibleToBuf(caller_roles);
  ccf.kv[roles_table].set(raw_target_id, raw_caller_roles);

  return {
    statusCode: 204,
  };
}
