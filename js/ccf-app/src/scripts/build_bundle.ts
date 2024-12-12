import { readdirSync, statSync, readFileSync, writeFileSync } from "fs";
import { join, posix, resolve, sep } from "path";

function getAllFiles(dirPath : string) : string[] {
  const toSearch = [dirPath];
  const agg = [];

  for (const filePath of toSearch) {
    if (statSync(filePath).isDirectory()) {
      for (const subfile of readdirSync(filePath)){
          toSearch.push(join(filePath, subfile));
      }
    } else {
      agg.push(filePath);
    }
  }
  return agg
}

function removePrefix(s : string, prefix : string) : string {
  if (s.startsWith(prefix)) {
    return s.slice(prefix.length).split(sep).join(posix.sep);
  }
  console.log("Warn: tried to remove invalid prefix", s, prefix);
  return s;
}

const args = process.argv.slice(2);

const rootDirPath = resolve(args[0]);
const metadataPath = join(rootDirPath, "app.json");

const metadata = JSON.parse(readFileSync(metadataPath, "utf-8"));

const srcDir = join(rootDirPath, "src");
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
  `Writing bundle containing ${modules.length} modules to ${bundlePath}`,
);
writeFileSync(bundlePath, JSON.stringify(bundle));