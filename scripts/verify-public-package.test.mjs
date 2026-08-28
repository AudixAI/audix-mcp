import assert from "node:assert/strict";
import test from "node:test";

import { findForbiddenContent } from "./verify-public-package.mjs";

test("detects every supported credential family without storing real-looking fixtures", () => {
  const candidates = [
    ["private key", `-----BEGIN ${"PRIVATE"} KEY-----`],
    ["AWS access key", `AK${"IA"}${"A".repeat(16)}`],
    ["GitHub token", `gh${"p_"}${"A".repeat(24)}`],
    ["fine-grained GitHub token", `github_${"pat_"}${"A".repeat(24)}`],
    ["npm token", `npm${"_"}${"A".repeat(24)}`],
    ["OpenAI-style API key", `sk${"-proj-"}${"A".repeat(24)}`],
    ["Slack token", `xox${"b-"}${"A".repeat(24)}`],
  ];

  for (const [expectedLabel, candidate] of candidates) {
    assert.ok(
      findForbiddenContent(candidate).includes(expectedLabel),
      `${expectedLabel} was not detected`,
    );
  }
});

test("detects private implementation and rollout metadata", () => {
  const labels = findForbiddenContent(
    [
      "private repository",
      "AUD-123",
      "PR #456",
      "decision D-M4",
      "https://staging.example.invalid/api",
      "/Users/developer/project",
      "goalEvidence",
    ].join("\n"),
  );

  assert.deepEqual(
    [
      "private implementation reference",
      "private work tracker reference",
      "private pull request reference",
      "private design decision label",
      "non-production deployment reference",
      "developer home path",
      "internal rollout metadata",
    ],
    labels,
  );
});

test("allows ordinary public MCP documentation and JavaScript", () => {
  assert.deepEqual(
    [],
    findForbiddenContent(
      "Audix MCP uploads a project, starts a scan, and returns a fuzz harness.",
    ),
  );
});
