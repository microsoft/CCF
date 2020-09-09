import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
  input: 'src/endpoints.js',
  output: {
    dir: 'dist',
    format: 'es',
    preserveModules: true
  },
  plugins: [
    commonjs(),
    nodeResolve()
  ]
};