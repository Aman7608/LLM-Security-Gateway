/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Where the gateway API runs while developing (uvicorn's default address)
const API = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    // The dev server passes API calls on to the gateway. To the browser,
    // the dashboard and the API then have the same address, so the API
    // does not need to allow other websites (no CORS settings to get wrong).
    proxy: {
      "/v1": API,
      "/health": API,
      "/ready": API,
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
  },
});
