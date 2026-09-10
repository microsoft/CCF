export function recursive(request) {
  const depth = request.body.json()["depth"];
  _recursive(depth);
  return {};
}

function _recursive(depth) {
  if (depth > 0) {
    _recursive(depth - 1);
  }
}

export function alloc(request) {
  const size = request.body.json()["size"];
  new Uint8Array(size);
  return {};
}

export function sleep(request) {
  const time = request.body.json()["time"];
  ccf.enableUntrustedDateTime(true);
  const start = new Date();
  while (true) {
    const now = new Date();
    const diff = now - start;
    if (diff > time) {
      break;
    }
  }
  return {};
}

export function nestedEval() {
  eval("while (true) {}");
  return {};
}

export function nestedFunction() {
  Function("while (true) {}")();
  return {};
}

export function responseBodyGetter() {
  return {
    get body() {
      while (true) {}
    },
  };
}

export function responseHeadersGetter() {
  return {
    get headers() {
      while (true) {}
    },
  };
}

export function responseHeaderValueGetter() {
  return {
    headers: {
      get value() {
        while (true) {}
      },
    },
  };
}

export function responseHeadersProxy() {
  return {
    headers: new Proxy(
      {},
      {
        ownKeys() {
          while (true) {}
        },
      },
    ),
  };
}

export function responseStatusCodeGetter() {
  return {
    get statusCode() {
      while (true) {}
    },
  };
}

export function responseGetterThrows() {
  return {
    get body() {
      throw new Error("boom");
    },
  };
}
