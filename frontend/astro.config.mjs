import { defineConfig } from "astro/config";

const backendTarget = process.env.DOCKERVIEW_LOCAL_SERVER_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  output: "static",
  build: { format: "directory" },
  vite: {
    server: {
      proxy: {
        "/api": {
          target: backendTarget,
          ws: true,
        },
      },
    },
  },
});
