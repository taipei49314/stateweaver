import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const APP_ORIGIN = "http://127.0.0.1:4173";
const API_PATHS = new Set([
  "/v1/demo/overview",
  "/v1/demo/worlds",
  "/v1/demo/twin",
  "/v1/demo/replay",
]);

type BrowserHealth = {
  consoleErrors: string[];
  pageErrors: string[];
  boundaryViolations: string[];
};

function watchBrowserHealth(page: Page): BrowserHealth {
  const health: BrowserHealth = {
    consoleErrors: [],
    pageErrors: [],
    boundaryViolations: [],
  };
  page.on("console", (message) => {
    if (message.type() === "error") health.consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => health.pageErrors.push(error.message));
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== APP_ORIGIN)
      health.boundaryViolations.push(request.url());
    if (url.pathname.startsWith("/v1/") && !API_PATHS.has(url.pathname)) {
      health.boundaryViolations.push(request.url());
    }
    if (url.pathname.startsWith("/v1/") && request.method() !== "GET") {
      health.boundaryViolations.push(`${request.method()} ${request.url()}`);
    }
  });
  return health;
}

async function expectHealthy(health: BrowserHealth): Promise<void> {
  expect(health.consoleErrors, "browser console errors").toEqual([]);
  expect(health.pageErrors, "uncaught page errors").toEqual([]);
  expect(
    health.boundaryViolations,
    "non-loopback or non-fixed API requests",
  ).toEqual([]);
}

async function openReadyOverview(page: Page): Promise<void> {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Deterministic state exploration" }),
  ).toBeVisible();
  await expect(page.getByText("LOCAL SYNTHETIC LAB")).toBeVisible();
}

const workspaceRoutes = [
  ["/", "Experiment Overview", "Deterministic state exploration"],
  ["/worlds", "World DAG", "materialized-01"],
  ["/twin", "Twin Inspector", "Twin Inspector"],
  ["/replay", "Replay / Evidence", "Clean-root replay"],
] as const;

test("desktop shell stays within the viewport and has zero browser errors @desktop", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  await openReadyOverview(page);

  await expect(
    page.getByRole("navigation", { name: "Primary workspace" }),
  ).toBeVisible();
  await expect(page.getByRole("main")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
    "desktop document has no horizontal overflow",
  ).toBe(true);
  await expectHealthy(health);
});

test("mobile workspace remains readable and contained @mobile", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  await openReadyOverview(page);

  await expect(
    page.getByRole("button", { name: "Open World DAG" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
    "mobile document has no page-level horizontal overflow",
  ).toBe(true);
  await page.getByRole("button", { name: "Open World DAG" }).tap();
  await expect(page).toHaveURL(`${APP_ORIGIN}/worlds`);
  await expect(
    page.getByRole("button", { name: /materialized-01/i }),
  ).toBeVisible();
  await expectHealthy(health);
});

test("keyboard navigation reaches every workspace route @desktop", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  await openReadyOverview(page);

  for (const [route, label, heading] of workspaceRoutes) {
    const active = page.getByRole("button", { name: label, exact: true });
    await active.focus();
    await expect(active).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(`${APP_ORIGIN}${route}`);
    await expect(active).toHaveAttribute("aria-current", "page");
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
  }
  await expectHealthy(health);
});

test("all workspace routes pass WCAG A/AA and browser health @all", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  for (const [route, label, heading] of workspaceRoutes) {
    await page.goto(route);
    await expect(
      page.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: label, exact: true }),
    ).toHaveAttribute("aria-current", "page");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
      `${route} has no page-level horizontal overflow`,
    ).toBe(true);
    const result = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();
    expect(
      result.violations.map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        nodes: violation.nodes.map((node) => node.target),
      })),
      `${route} has no WCAG A/AA violations`,
    ).toEqual([]);
  }
  await expectHealthy(health);
});

test("loading waits for the sealed overview before rendering data @desktop", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  let releaseRequest: (() => void) | undefined;
  const held = new Promise<void>((resolve) => {
    releaseRequest = resolve;
  });
  await page.route("**/v1/demo/overview", async (route) => {
    await held;
    const response = await route.fetch();
    await route.fulfill({ response });
  });

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Loading saved fixture" }),
  ).toBeVisible();
  releaseRequest?.();
  await expect(
    page.getByRole("heading", { name: "Deterministic state exploration" }),
  ).toBeVisible();
  await expectHealthy(health);
});

test("fixed API failure remains a bounded synthetic error state @desktop", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  await page.route("**/v1/demo/overview", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: "{}" }),
  );

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Saved fixture unavailable" }),
  ).toBeVisible();
  await expect(page.getByText("Invalid fixture")).toBeVisible();
  await expect(page.getByText("SYNTHETIC LOCAL LAB")).toBeVisible();
  await expectHealthy(health);
});

test("empty World DAG filters show an explicit bounded state @desktop", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  await openReadyOverview(page);
  await page.getByRole("button", { name: "World DAG", exact: true }).click();

  for (const tier of ["ROOT", "GHOST", "REPLAY", "SIMULATED", "MATERIALIZED"]) {
    await page.getByRole("checkbox", { name: tier, exact: true }).uncheck();
  }
  await expect(
    page.getByRole("heading", { name: "No visible node" }),
  ).toBeVisible();
  await expect(page.getByText("Enable a world tier to inspect.")).toBeVisible();
  await expect(page.locator(".dag-node")).toHaveCount(0);
  await expectHealthy(health);
});

test("digest substitution fails closed before any workspace data renders @desktop", async ({
  page,
}) => {
  const health = watchBrowserHealth(page);
  await page.route("**/v1/demo/overview", async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as {
      stages: Array<{ evidence_digest: string }>;
    };
    body.stages[0].evidence_digest = "f".repeat(64);
    await route.fulfill({ response, json: body });
  });

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Saved fixture unavailable" }),
  ).toBeVisible();
  await expect(page.getByText("Stage digest mismatch")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Deterministic state exploration" }),
  ).not.toBeVisible();
  await expectHealthy(health);
});
