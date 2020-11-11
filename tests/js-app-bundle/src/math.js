function compute_impl(op, left, right) {
  let result;
  if (op == "add") result = left + right;
  else if (op == "sub") result = left - right;
  else if (op == "mul") result = left * right;
  else {
    return {
      statusCode: 400,
      body: {
        error: "unknown op",
      },
    };
  }

  return {
    body: {
      result: result,
    },
  };
}

export function compute(request) {
  const body = request.body.json();

  if (typeof body.left != "number" || typeof body.right != "number") {
    return {
      statusCode: 400,
      body: {
        error: "invalid operand type",
      },
    };
  }

  return compute_impl(body.op, body.left, body.right);
}

export function compute2(request) {
  const params = request.params;

  // Type of params is always string. Try to parse as float
  let left = parseFloat(params.left);
  if (isNaN(left)) {
    return {
      statusCode: 400,
      body: {
        error: "left operand is not a parseable number",
      },
    };
  }

  let right = parseFloat(params.right);
  if (isNaN(right)) {
    return {
      statusCode: 400,
      body: {
        error: "right operand is not a parseable number",
      },
    };
  }

  return compute_impl(params.op, left, right);
}
