import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import babel from 'rollup-plugin-babel';
import json from 'rollup-plugin-json';
import { uglify } from 'rollup-plugin-uglify';

export default {
  input: `./src/index.js`,
  output: {
    name: 'fernet',
    file: `./dist/index.js`,
    format: 'cjs',
  },
  plugins: [
    resolve({
      jsnext: true,
      main: true,
      browser: true
    }),
    commonjs(), // so Rollup can convert `ms` to an ES module
    json(),
    babel({
      babelrc: false,
      exclude: 'node_modules/**',
      runtimeHelpers: true,
      plugins: ['transform-runtime', 'transform-async-to-generator'],
      presets: [['env', { modules: false }]]
    }),
    uglify(),
  ]
}