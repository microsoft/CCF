This folder defines a new governance API.

It aims to expose all of the functionality of the existing API, defined in `src/node/rpc/member_frontend.h`, but with naming and schemas compliant with Azure API standards.

For a transition period (at least the 4.x release), both APIs will be offered. The plan is to eventually deprecate the old API.

Implementation notes:
- All endpoints validate and process an `api-version` parameter, modifying their behaviour accordingly.
- To present both under the `/gov` prefix, the old frontend is rewritten to be a subclass of the new frontend.
- Aiming to split the frontend implementation into distinct components which can be more easily moved around, rather than a single monolithic frontend implementation.