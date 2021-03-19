import { nodeResolve } from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";

export default {
  input: "build/endpoints.ts",
  output: {
    dir: "dist/src",
    format: "es",
    preserveModules: true,
    preserveModulesRoot: 'build'
  },
  plugins: [nodeResolve(), typescript(), commonjs()],
};
