import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  base: "/static/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    proxy: {
      "/auth": "http://127.0.0.1:8000",
      "/agents": "http://127.0.0.1:8000",
      "/admin": "http://127.0.0.1:8000",
      "/resource": "http://127.0.0.1:8000",
      "/tasks": "http://127.0.0.1:8000",
      "/integrations": "http://127.0.0.1:8000",
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
      "/healthz": "http://127.0.0.1:8000",
      "/api": "http://127.0.0.1:8000",
      "/docs": "http://127.0.0.1:8000",
      "/openapi.json": "http://127.0.0.1:8000",
    },
  },
});
