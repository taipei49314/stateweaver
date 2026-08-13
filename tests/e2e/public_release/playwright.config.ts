import { defineConfig, devices } from "@playwright/test";
import os from "node:os";
import path from "node:path";

const APP_ORIGIN = "http://127.0.0.1:4173";

if (process.env.PLAYWRIGHT_TEST_BASE_URL) {
  throw new Error("M8 browser admission does not accept a caller-supplied URL");
}

export default defineConfig({
  testDir: ".",
  testMatch: "m8_public_ux.spec.ts",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  outputDir: path.join(os.tmpdir(), "stateweaver-m8-playwright"),
  reporter: [["line"]],
  use: {
    baseURL: APP_ORIGIN,
    screenshot: "on",
    trace: "retain-on-failure",
    video: "off",
  },
  projects: [
    {
      name: "desktop-chromium",
      grep: /@desktop|@all/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "mobile-chromium",
      grep: /@mobile|@all/,
      use: { ...devices["Pixel 7"] },
    },
  ],
  webServer: [
    {
      command:
        "uv run --project ../../../apps/api uvicorn stateweaver_api.app:app --app-dir ../../../apps/api/src --host 127.0.0.1 --port 8000",
      url: "http://127.0.0.1:8000/healthz",
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command:
        "npm --prefix ../../../apps/web run preview -- --host 127.0.0.1 --port 4173 --strictPort",
      url: APP_ORIGIN,
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
