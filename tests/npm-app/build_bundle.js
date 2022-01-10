import { readdirSync, statSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

const args = process.argv.slice(2);

const getAllFiles = function (dirPath, arrayOfFiles) {
  var files = readdirSync(dirPath);

  arrayOfFiles = arrayOfFiles || [];

  files.forEach(function (file) {
    const filePath = join(dirPath, file);
    if (statSync(filePath).isDirectory()) {
      arrayOfFiles = getAllFiles(filePath, arrayOfFiles);
    } else {
      arrayOfFiles.push(filePath);
    }
  });

  return arrayOfFiles;
};

const removePrefix = function (s, prefix) {
  return s.substr(prefix.length);
};

const rootDir = args[0];

const metadataPath = join(rootDir, "app.json");
const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));

const srcDir = join(rootDir, "src", "/");
const allFiles = getAllFiles(srcDir);

const modules = allFiles.map(function (filePath) {
  return {
    name: removePrefix(filePath, srcDir),
    module: readFileSync(filePath, "utf-8"),
  };
});

const bundlePath = join(args[0], "bundle.json");
const bundle = 
{
  metadata: metadata,
  modules: modules,
};
console.log(`Writing bundle containing ${modules.length} modules to ${bundlePath}`);
writeFileSync(bundlePath, JSON.stringify(bundle));
