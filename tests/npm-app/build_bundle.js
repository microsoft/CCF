import { readdirSync, statSync, readFileSync, writeFileSync } from "fs";
import { join, posix, sep } from "path";

const args = process.argv.slice(2);

const getAllFiles = function (dirPath, arrayOfFiles) {
  arrayOfFiles = arrayOfFiles || [];

  const files = readdirSync(dirPath);
  for (const file of files) {
    const filePath = join(dirPath, file);
    if (statSync(filePath).isDirectory()) {
      arrayOfFiles = getAllFiles(filePath, arrayOfFiles);
    } else {
      arrayOfFiles.push(filePath);
    }
  }

  return arrayOfFiles;
};

const removePrefix = function (s, prefix) {
  return s.substr(prefix.length).split(sep).join(posix.sep);
};

const rootDir = args[0];

const metadataPath = join(rootDir, "app.json");
const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));

const srcDir = join(rootDir, "src");
const allFiles = getAllFiles(srcDir);

// The trailing / is included so that it is trimmed in removePrefix.
// This produces "foo/bar.js" rather than "/foo/bar.js"
const toTrim = srcDir + "/";

const modules = allFiles.map(function (filePath) {
  return {
    name: removePrefix(filePath, toTrim),
    module: readFileSync(filePath, "utf-8"),
  };
});

const bundlePath = join(args[0], "bundle.json");
const bundle = {
  metadata: metadata,
  modules: modules,
};
console.log(
  `Writing bundle containing ${modules.length} modules to ${bundlePath}`
);
writeFileSync(bundlePath, JSON.stringify(bundle));
