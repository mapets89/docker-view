# Development

Run `make dev` for the Compose workflow or run Astro and the two Go binaries separately with a strong shared `DOCKERVIEW_GATEWAY_SECRET`. Required checks are `make test lint typecheck security`.

Versions are pinned: Go module language 1.25 (digest-pinned Go 1.26.8 Alpine builder), Astro 7.3.1, digest-pinned Node 26 Alpine builder, TypeScript 7.0.2 native, xterm.js 6.0.0, chi 5.2.2, Moby client 0.6.0/API 1.56.0, and modernc SQLite 1.38.2. Lockfiles are committed.

TypeScript 7.0 does not expose a programmatic compiler API. Astro's checker explicitly still needs TypeScript 6. DockerView follows Microsoft's side-by-side recommendation: `@typescript/native` supplies the TS7 `tsc`; the `typescript` alias supplies `@typescript/typescript6` only to template/lint tooling. `npm run check` runs both Astro check and native TS7 typecheck.
