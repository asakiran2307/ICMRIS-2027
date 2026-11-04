const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

test("conference application entry points are present", () => {
  for (const file of [
    "index.html",
    "portal.js",
    "admin-setup.html",
    "certificate.html",
    "api/[...path].js",
    "api/admin/bootstrap.js",
  ]) {
    assert.ok(fs.existsSync(path.join(root, file)), `Missing required file: ${file}`);
  }
});

test("package metadata and test command are valid", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.equal(pkg.name, "icmris-2027");
  assert.equal(pkg.scripts?.test, "node --test");
  for (const dependency of ["@vercel/blob", "bcryptjs", "jsonwebtoken", "pg"]) {
    assert.ok(pkg.dependencies?.[dependency], `Missing runtime dependency: ${dependency}`);
  }
});

test("all application JavaScript files pass Node syntax checks", () => {
  for (const file of ["portal.js", "api/[...path].js", "api/admin/bootstrap.js"]) {
    const result = spawnSync(process.execPath, ["--check", path.join(root, file)], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `${file} syntax check failed:\n${result.stderr}${result.stdout}`);
  }
});

test("inline JavaScript in HTML pages parses without syntax errors", () => {
  let checked = 0;
  for (const file of ["index.html", "admin-setup.html", "certificate.html"]) {
    const html = read(file);
    const scripts = html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi);
    for (const match of scripts) {
      if (/\bsrc\s*=/.test(match[1])) continue;
      const source = match[2].trim();
      if (!source) continue;
      assert.doesNotThrow(
        () => new vm.Script(source, { filename: file }),
        `Inline script syntax failed in ${file}`,
      );
      checked += 1;
    }
  }
  assert.ok(checked > 0, "Expected to find inline scripts to validate");
});

test("serverless API exposes the expected core route handlers", () => {
  const api = read("api/[...path].js");
  for (const route of [
    'path==="health"',
    'path==="auth/register"',
    'path==="auth/login"',
    'path==="admin/bootstrap"',
    'path==="submissions"',
    'path==="reviews"',
  ]) {
    assert.ok(api.includes(route), `Expected API route not found: ${route}`);
  }
});
