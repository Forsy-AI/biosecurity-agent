import { access, readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("public source boundary", () => {
  it("keeps only intentional extension packages and excludes release-only data", async () => {
    const packageDirectories = (await readdir(resolve(root, "packages"), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();

    expect(packageDirectories).toEqual(["agent-adapters", "contracts", "safety"]);

    const gitignore = await readFile(resolve(root, ".gitignore"), "utf8");
    expect(gitignore.split(/\r?\n/)).toContain("huggingface-dataset-01/");

    const readme = await readFile(resolve(root, "README.md"), "utf8");
    expect(readme).toContain("assets/bioworld.png");
    expect(readme).toContain("assets/terminal-replay.log");
    expect(readme).not.toContain("assets/living-world.png");

    await expect(access(resolve(root, "assets/bioworld.png"))).resolves.toBeUndefined();
    await expect(access(resolve(root, "assets/terminal-replay.log"))).resolves.toBeUndefined();
  });
});
