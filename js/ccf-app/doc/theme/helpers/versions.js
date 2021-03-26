/* Test without sphinx-multiversion:
export SMV_CURRENT_VERSION=ccf-0.19.1
export SMV_METADATA_PATH=$(pwd)/doc/theme/helpers/versions.sample.json
npm run docs:serve
*/

const fs = require("fs");

function sortByNameDesc(arr) {
  arr.sort((a, b) => a.name.localeCompare(b.name));
  arr.reverse();
}

const metadataPath = process.env.SMV_METADATA_PATH;
let versions = null;
if (metadataPath) {
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  versions = {
    branches: Object.values(metadata).filter((v) => v.source != "tags"),
    tags: Object.values(metadata).filter((v) => v.source == "tags"),
    currentVersion: process.env.SMV_CURRENT_VERSION,
  };
  sortByNameDesc(versions.branches);
  sortByNameDesc(versions.tags);
}

module.exports = {
  versions: function (options) {
    return versions;
  },
};
