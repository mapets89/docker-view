# V1 implementation decisions

## TypeScript 7 and Astro

TypeScript 7 is the native compiler used by `npm run typecheck`. Astro's current language tooling still requires the TypeScript 6 programmatic API, so the frontend keeps TypeScript 6 under an explicit compatibility alias solely for `astro check` and ESLint. Application compilation is independently verified with TypeScript 7. This can be removed when Astro supports the native API.

## Host disk metric

DockerView deliberately reports host disk as **Not exposed** in V1. Reading host filesystem capacity would require another privileged host mount or a broader Gateway host API, increasing the impact of a compromise. CPU and memory come from the Docker Engine info API. A future host agent can expose a narrowly scoped disk metric without mounting the host filesystem into the public Server.

## Docker socket boundary

The Gateway is intentionally not a transparent Docker API proxy. Every accepted operation and exec parameter is enumerated in code. This omits otherwise convenient Docker operations because socket access is equivalent to a highly privileged host capability.
