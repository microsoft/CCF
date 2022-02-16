const fs = require("fs");
const path = require("path");

const args = process.argv.slice(2);

const getAllFiles = function (dirPath, arrayOfFiles) {
  arrayOfFiles = arrayOfFiles || [];

  const files = fs.readdirSync(dirPath);
  for (const file of files) {
    const filePath = path.join(dirPath, file);
    if (fs.statSync(filePath).isDirectory()) {
      arrayOfFiles = getAllFiles(filePath, arrayOfFiles);
    } else {
      arrayOfFiles.push(filePath);
    }
  }

  return arrayOfFiles;
};

const removePrefix = function (s, prefix) {
  return s.substr(prefix.length);
};

const rootDir = args[0];

const metadataPath = path.join(rootDir, "app.json");
const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf-8"));

const srcDir = path.join(rootDir, "src");
const allFiles = getAllFiles(srcDir);

// The trailing / is included so that it is trimmed in removePrefix.
// This produces "foo/bar.js" rather than "/foo/bar.js"
const toTrim = srcDir + "/";

const modules = allFiles.map(function (filePath) {
  return {
    name: removePrefix(filePath, toTrim),
    module: fs.readFileSync(filePath, "utf-8"),
  };
});

const bundlePath = path.join(args[0], "bundle.json");
const bundle = {
  metadata: metadata,
  modules: modules,
};
console.log(
  `Writing bundle containing ${modules.length} modules to ${bundlePath}`
);
fs.writeFileSync(bundlePath, JSON.stringify(bundle));
