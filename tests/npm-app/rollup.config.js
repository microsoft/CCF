import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';

export default {
  input: 'src/endpoints.ts',
  output: {
    dir: 'dist',
    format: 'es',
    preserveModules: true
  },
  plugins: [
    nodeResolve(),
    typescript(),
    commonjs(),
  ]
};