import { expect, test } from "@playwright/test";

test.beforeEach(async ({ request }) => {
  const started = await request.post("http://127.0.0.1:7331/api/demo/start", { data: {} });
  const runId = (await started.json()).runId as string;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const response = await request.get(`http://127.0.0.1:7331/api/runs/${runId}`);
    const world = await response.json();
    if (
      world.phase === "live" &&
      world.protections.length > 0 &&
      world.snapshots.some((snapshot: any) => snapshot.simulation)
    )
      return;
    await new Promise((done) => setTimeout(done, 80));
  }
  throw new Error("Demo world did not become live");
});

test("optional viewer renders the same persisted world and exposes evidence", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("VISUAL WORLD · CONTROLS LIVE IN THE CLI")).toBeVisible();
  await expect(page.getByText("SIMULATION · +14 DAYS")).toBeVisible();
  await expect(page.getByText("PROTECTION")).toBeVisible();
  await expect(page.getByText(/sources/).first()).toBeVisible();
  await expect(page.getByText("MEANINGFUL PIPELINE EVENTS")).toBeVisible();
  await expect(page.locator(".adaptive-visual")).toBeVisible();
  await page.locator(".map-marker").first().click();
  await expect(page.locator(".evidence-panel")).toBeVisible();
  await expect(page.getByText("Target relevance")).toBeVisible();
  await page.screenshot({ path: "test-results/visual-viewer.png", fullPage: true });
});

test("viewer remains a single read-only visual page on mobile", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByText("VISUAL WORLD · CONTROLS LIVE IN THE CLI")).toBeVisible();
  await expect(page.locator("form, input, select, textarea")).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /start|add target|configure|approve/i }),
  ).toHaveCount(0);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});
