import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'

export default [
  {
    input: 'dist/index.js',
    output: {
      file: 'dist/index.js',
      format: 'esm',
    },
    plugins: [resolve(), commonjs(), json()],
  },
]
