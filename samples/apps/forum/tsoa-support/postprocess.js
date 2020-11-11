import * as fs from "fs";
import * as path from "path";
import SwaggerParser from "@apidevtools/swagger-parser";

// endpoint metadata defaults when first added to endpoints.json
const metadataDefaults = (readonly) => ({
  forwarding_required: "always",
  execute_locally: false,
  require_client_identity: true,
  require_client_signature: false,
  readonly: readonly,
});

const distDir = "./dist";

// generated by tsoa from code
const openapiPath = "./build/swagger.json";

// generated by tsoa using routes.ts.tmpl
const routesPath = "./build/routes.ts";

// special markers in generated routes.ts
const markerHelpersStart = "// CCF:HELPERS-START";
const markerHelpersEnd = "// CCF:HELPERS-END";
const markerMetadataStart = "// CCF:METADATA-START";
const markerMetadataEnd = "// CCF:METADATA-END";
const markerControllerStart = "// CCF:CONTROLLER-START=";
const markerControllerEnd = "// CCF:CONTROLLER-END";

// files generated by this script
const helpersPath = "./build/helpers.ts";
const controllerProxyPath = "./build/{}Proxy.ts";
const endpointsPath = "./build/endpoints.ts";
const metadataPath = "./app.tmpl.json";
const finalMetadataPath = `${distDir}/app.json`;

// read generated routes.ts
const file = fs.readFileSync(routesPath, "utf8");

// copy helpers script part to separate file
const helpersStartIdx = file.indexOf(markerHelpersStart);
const helpersEndIdx = file.indexOf(markerHelpersEnd, helpersStartIdx);
const helpersCode = file.substring(
  helpersStartIdx + markerHelpersStart.length,
  helpersEndIdx
);
fs.writeFileSync(helpersPath, helpersCode);

// copy controller script parts to separate files
let controllerStartIdx = 0;
const proxyPaths = [];
while (true) {
  controllerStartIdx = file.indexOf(markerControllerStart, controllerStartIdx);
  if (controllerStartIdx === -1) break;
  const controllerEndIdx = file.indexOf(
    markerControllerEnd,
    controllerStartIdx
  );
  if (controllerEndIdx === -1)
    throw new Error(`'${markerControllerEnd}' not found`);
  const controllerNameEndIdx = file.indexOf("\n", controllerStartIdx);
  const controllerName = file
    .substring(
      controllerStartIdx + markerControllerStart.length,
      controllerNameEndIdx
    )
    .trim();
  const controllerCode = file.substring(controllerNameEndIdx, controllerEndIdx);
  const proxyPath = controllerProxyPath.replace("{}", controllerName);
  proxyPaths.push(proxyPath);
  fs.writeFileSync(proxyPath, controllerCode);
  controllerStartIdx = controllerEndIdx;
}

// create build/endpoints.ts (only needed for rollup as entry point)
let endpointsCode = "";
for (const proxyPath of proxyPaths) {
  const proxyName = path.basename(proxyPath, ".ts");
  endpointsCode += `export * as ${proxyName} from './${proxyName}';\n`;
}
fs.writeFileSync(endpointsPath, endpointsCode);

// Create/update app.json which maps
// URL + METHOD -> module name + function.
const metadataStartIdx = file.indexOf(markerMetadataStart);
const metadataEndIdx = file.indexOf(markerMetadataEnd, metadataStartIdx);
const metadataJson = file.substring(
  metadataStartIdx + markerMetadataStart.length,
  metadataEndIdx
);
let newMetadata = JSON.parse(metadataJson);

// tsoa groups routes by controllers and actions.
// For app.json, we need to group by url and method instead.
let tmp = { endpoints: {} };
for (let controller of newMetadata.controllers) {
  for (let action of controller.actions) {
    // transform /a/:b/:c to /a/{b}/{c}
    let url = action.full_path.replace(/:([^\/]+)/g, (_, name) => `{${name}}`);
    if (!tmp.endpoints[url]) {
      tmp.endpoints[url] = {};
    }
    tmp.endpoints[url][action.method] = {
      js_module: controller.js_module,
      js_function: action.js_function,
    };
  }
}
newMetadata = tmp;

let oldMetadata = { endpoints: {} };
if (fs.existsSync(metadataPath)) {
  oldMetadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
}
const oldEndpoints = oldMetadata["endpoints"];
const newEndpoints = newMetadata["endpoints"];
for (const url in newEndpoints) {
  for (const method in newEndpoints[url]) {
    const readonly = method == "get";
    Object.assign(newEndpoints[url][method], metadataDefaults(readonly));
  }
}
console.log(`Updating ${metadataPath} (if needed)`);
let wasUpdated = false;
for (const url in oldEndpoints) {
  if (!(url in newEndpoints)) {
    console.log(`Removed: ${url}`);
    wasUpdated = true;
  }
}
for (const url in newEndpoints) {
  if (!(url in oldEndpoints)) {
    console.log(`Added: ${url}`);
    wasUpdated = true;
    continue;
  }
  const oldMethods = oldEndpoints[url];
  const newMethods = newEndpoints[url];
  for (const method in oldMethods) {
    if (!(method in newMethods)) {
      console.log(`Removed: ${url} [${method}]`);
      wasUpdated = true;
    }
  }
  for (const method in newMethods) {
    if (!(method in oldMethods)) {
      console.log(`Added: ${url} [${method}]`);
      wasUpdated = true;
      continue;
    }
    // Copy from old but update module & function
    const oldCfg = oldMethods[method];
    const newCfg = newMethods[method];
    if (
      oldCfg["js_module"] != newCfg["js_module"] ||
      oldCfg["js_function"] != newCfg["js_function"]
    ) {
      oldCfg["js_module"] = newCfg["js_module"];
      oldCfg["js_function"] = newCfg["js_function"];
      console.log(`Updated: ${url} [${method}]`);
      wasUpdated = true;
    } else {
      console.log(`Unchanged: ${url} [${method}]`);
    }
    newMethods[method] = oldCfg;
  }
}
if (wasUpdated) {
  fs.writeFileSync(metadataPath, JSON.stringify(newMetadata, null, 2));
}

// delete routes.ts since its content is now split into multiple files
fs.unlinkSync(routesPath);

// create dist/endpoints.json which includes stand-alone OpenAPI Operation objects
// for each endpoint
SwaggerParser.dereference(openapiPath)
  .then((openapi) => {
    for (const url in newEndpoints) {
      const pathItem = openapi.paths[url] || {};
      for (const method in newEndpoints[url]) {
        let operation = pathItem[method];
        if (!operation) {
          console.log(
            `WARNING: ${url} [${method}] not found in OpenAPI document`
          );
          operation = null;
        }
        if (!newEndpoints[url][method]["openapi"])
          newEndpoints[url][method]["openapi"] = operation;
      }
    }
    fs.mkdirSync(distDir, { recursive: true });
    fs.writeFileSync(finalMetadataPath, JSON.stringify(newMetadata, null, 2));
  })
  .catch((e) => {
    console.error(`${e}`);
    process.exit(1);
  });
