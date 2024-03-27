import { nodeResolve } from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";

export default {
  input: "src/endpoints/all.ts",
  output: {
    dir: "dist/src",
    format: "es",
    preserveModules: true,
    preserveModulesRoot: "src",
  },
  plugins: [
    nodeResolve(),
    typescript({ compilerOptions: { noEmitOnError: true } }),
    commonjs(),
  ],
};
