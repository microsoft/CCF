# Node.js/npm CCF app using tsoa

This folder contains a sample CCF app written in TypeScript with [tsoa](https://tsoa-community.github.io/docs/).
See the [README.md](../npm-app/README.md) file of the `npm-app` folder for a general introduction to CCF's JavaScript environment and npm.

tsoa generates OpenAPI definitions from TypeScript types and JSDoc annotations.
It also uses the generated schemas to validate the request data.

Note that tsoa currently focuses on JSON as content type.
Using other content types is possible but requires to manually specify the OpenAPI definition.
See [`proto.ts`](src/controllers/proto.ts) for details.

Additional CCF-specific metadata is specified in `endpoints.json`.
When new endpoints are added in the TypeScript code, then those get automatically added to `endpoints.json`
when running `npm run build`.
Note that most of the metadata is still unused as support for it is missing in CCF for JS apps.
This will be addressed in the near future.

See the `modules.py` test for how this app is built and deployed to CCF.
