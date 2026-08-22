import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: "pnpm dev",
    // The viewer can start before the API. Waiting on runtime health prevents
    // the first journey from racing the local server during cold starts.
    url: "http://127.0.0.1:7331/api/health",
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
