# StateWeaver public workspace

Read-only Vite client for the built-in synthetic fixture. It only fetches the fixed relative GET API
surface and has no target, credential, command, or mutation controls. Before rendering, it
recomputes canonical Web Crypto SHA-256 for the fixed run identity, every content-bound digest,
the evidence manifest, and the five-run signature, then closes relations across all four responses.

`npm ci && npm run dev` starts the local UI; the development proxy targets `127.0.0.1:8000`.

Local gates:

```text
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
```

The accepted concepts and browser fidelity ledger live under `design/`. These checks establish
local synthetic fixture integrity only; they are not materialized replay proof or release
certification.
