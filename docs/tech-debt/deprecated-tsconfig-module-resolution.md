# Tech Debt: Deprecated `moduleResolution: "node"` in tsconfig.json

## Problem

`tsconfig.json` uses `"moduleResolution": "node"`, the legacy module resolution strategy.
TypeScript 5.x marks it as deprecated. For ESM packages (`"type": "module"` in `package.json`),
the correct setting is `"moduleResolution": "node16"` or `"moduleResolution": "bundler"`.

## Where Code Lives

- `tsconfig.json:7` — `"moduleResolution": "node"`

## Risk

- TypeScript 6.0 is expected to remove or error on legacy `moduleResolution` settings
- Using `"node"` with ESM output can produce incorrect type resolution for packages that expose
  `exports` maps — `amqplib` uses one
- Currently masked by `"skipLibCheck": true`, which suppresses type errors from `node_modules`

## Suggested Fix

Change `"moduleResolution"` to `"node16"` and `"module"` to `"Node16"`:

```json
{
  "compilerOptions": {
    "module": "Node16",
    "moduleResolution": "node16"
  }
}
```

Note: `"node16"` requires relative imports in `src/` to use explicit `.js` extensions (per
Node.js ESM resolution rules). Run `npm run build` after the change to catch any missing
extensions.

## How to Change Safely

- Make the change in isolation on a `chore/` branch
- Fix any import extension errors surfaced by the compiler
- Run `npm run build` and `npm test` to verify no regressions
- This is a build-only change — it does not affect the published `dist/` behavior or consumers
