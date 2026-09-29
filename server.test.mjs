import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("./server.mjs", import.meta.url), "utf8");

test("OAuth and MCP security contract", () => {
  assert.match(source, /code_challenge_method/);
  assert.match(source, /timingSafeEqual/);
  assert.match(source, /resource_metadata/);
  assert.match(source, /verify\(match\?\.\[1\], "access"\)/);
  assert.doesNotMatch(source, /name:\s*"publish_to_threads"/);
  assert.doesNotMatch(source, /name:\s*"reply_to_threads"/);
});

test("approval sequence is enforced", () => {
  assert.match(source, /explicit_confirmation_required/);
  assert.match(source, /review_required_first/);
  assert.match(source, /approval_required_first/);
});
