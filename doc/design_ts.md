# OpenAPI for JS endpoints

OpenAPI examples: https://github.com/OAI/OpenAPI-Specification/tree/master/examples/v3.0

Previous work:

- https://github.com/microsoft/CCF/compare/master...eddyashton:openapi_generation

## Definitions

### Endpoint

An endpoint is a combination of URL path and HTTP method (GET, POST etc.).
URL paths may be templated.

## Requirements

Minimum:

- OpenAPI [Operation](https://swagger.io/specification/#operation-object) object per JS endpoint, provided manually, stored in kv with key being the URL path and HTTP method
- CCF-specific metadata (read-only etc.) in custom object, likely in outer object per endpoint:
  - {"ccf": {...}, "openapi": {...}}

Desirable:

- Automatic optional schema-based validation of body and possibly query parameters and header
- Named schemas to make OpenAPI doc more readable
- One of:
  - Automatic generation of OpenAPI description from TypeScript interfaces
  - Automatic generation of TypeScript interfaces from OpenAPI description
    - Requires schemas to be named, either via non-standard fields or storing/sharing named schemas

## Things to consider

Tools are generally based around full OpenAPI documents.
In CCF, multiple endpoints, including built-in ones, contribute to the final OpenAPI doc.
How this "contribution" will work work exactly in CCF is tbd, but any constraints around that
will influence the tooling we use/create for JS apps.

## Available tooling

Note that there seem to be no tools that can merge multiple independent OpenAPI documents into one,
apart from generic JSON Merge (https://tools.ietf.org/html/rfc7386) tools.
There is an open proposal in the OpenAPI spec repo on what merging may mean:
https://github.com/OAI/OpenAPI-Specification/issues/1442

### Validators

OpenAPI schema parsers/validators:

- JS: https://github.com/APIDevTools/swagger-parser^
  - supports bundling (resolves referenced URLs/files into internal `$ref`s)
  - supports dereferencing (inlines all `$ref`s)

OpenAPI payload validators:

- JS: https://github.com/byu-oit/openapi-enforcer

### Converters

TypeScript to JSON Schema:

- JS: https://github.com/YousefED/typescript-json-schema

JSON Schema to OpenAPI 3.0 Schema:

- JS: https://www.npmjs.com/package/@openapi-contrib/json-schema-to-openapi-schema
  - Note that OpenAPI 3.1 (rc0 released) is fully compatible with JSON schema.
    This library is only needed for <= 3.0.

OpenAPI to TypeScript:

- JS: https://github.com/manifoldco/swagger-to-ts
  - Supports custom mapping of properties via callbacks
- JS: https://github.com/ferdikoomen/openapi-typescript-codegen
- JS: https://github.com/Mermade/openapi-codegen

### Frameworks

- JS: https://github.com/lukeautry/tsoa
  - Top-level concept is a `Controller` which maps to a URL path
  - Converts TS to OpenAPI in an offline step
  - Uses TS annotations when types are not enough
  - Supports generation of custom middleware glue module
    - For CCF this would be a simple proxy
      https://github.com/lukeautry/tsoa/blob/master/packages/cli/src/routeGeneration/templates/express.hbs
      https://tsoa-community.github.io/docs/templates.html
  - Integrates payload validation
    - Error messages are not nice though
  - Supports binary data only via Node.js's `Buffer` type, not `ArrayBuffer` or typed arrays
    - Work-around is to access request object and provide OpenAPI definition manually
      https://tsoa-community.github.io/docs/file-upload.html
  - application/json is the only supported response content type in the generated OpenAPI doc
    - https://github.com/lukeautry/tsoa/blob/0b45240d386e7760edbf84933093518696453d0b/packages/cli/src/swagger/specGenerator3.ts#L289-L294
    - actual content type can be set during request

## Implementation options

### Automatic schema-based validation

Validation can either happen inside the JS endpoint, or in C++ before the endpoint is called.

#### Option A: JS validation

If validation happens in the JS endpoint then it becomes a JS tooling question, choosing the right JS library, avoiding boilerplate as much as possible, and ultimately it becomes the responsibility of the developer, though tooling created by the CCF team would try to reduce the burden.
JS validation code would either be proposed together with the actual endpoint code or separately in a "global" path to be accessible by all JS endpoints, e.g. `import {validate} from "/validation"`. In the latter case, such a library may be provided by the CCF team. Calling the validation library must happen explicitly at the beginning of the endpoint code. Tooling may automatically create wrapper functions to avoid visible boilerplate code.
Bugs in the validation code can be fixed through a JS update proposal.
A performance hit can be expected if schemas are large, though this may only be temporary until Wasm-based validator libraries exist and CCF supports Wasm.

#### Option B: C++ validation

If validation happens in C++ then it exclusively becomes a CCF team responsibility, choosing the right JSON Schema / OpenAPI C++ library (if one exists) and maintaining the code that integrates it.
Validation code would not be proposed (as it's built-in) and is guaranteed to be the same across all endpoints.
Bugs in the validation code can only be fixed by updating CCF.
The performance impact would be minimal, assuming the C/C++ library is efficient.

#### Option C: JS/C++ hybrid validation

A hybrid solution may be where a single CCF JS validation library is proposed and used for all endpoints.
This would mean that C++ would first call into the JS validation library and only if that succeeds into the endpoint. It can be seen as a special private endpoint that returns either `true` or throws an exception.
This solution essentially moves the boilerplate from the JS-only option for calling the validation library into C++.
Like in the C++ solution it would be guaranteed that the same validation code is used for all endpoints.
Validation could be enforced at the level of endpoint metadata, which would provide an option to enable/disable validation.
Bugs in the validation code can be fixed through a JS update proposal.
A performance hit can be expected if schemas are large, though this may only be temporary until Wasm-based validator libraries exist and CCF supports Wasm.

### Automatic generation of OpenAPI description from TypeScript interfaces
