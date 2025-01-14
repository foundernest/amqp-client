import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from "@rollup/plugin-json";

export default [
    {
        input: 'dist/esm/index.js',
        output: {
            file: 'dist/esm/index.js',
            format: 'esm'
        },
        plugins: [resolve(), commonjs(), json()]
    },
    {
        input: 'dist/cjs/index.js',
        output: {
            file: 'dist/cjs/index.js',
            format: 'cjs'
        },
        plugins: [resolve(), commonjs(), json()]
    }
];
