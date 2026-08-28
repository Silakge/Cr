import test from "node:test";
import assert from "node:assert/strict";

import {
  classifyRun,
  countKeywordOccurrences,
  estimateBase64Bytes,
  sanitizeUrl,
  scanText,
  scoreImageCandidate,
} from "../lib/core.js";

function runWith(events, denialAtMs = 1000) {
  return {
    status: "stopped",
    autoDenialAtMs: denialAtMs,
    manualDenialAtMs: null,
    events: events.map((event, index) => ({
      id: `e${index}`,
      ignored: false,
      candidate: true,
      strongConfidence: false,
      ...event,
    })),
  };
}

test("sanitizeUrl strips query strings, paths, and opaque asset identifiers", () => {
  const result = sanitizeUrl("https://cdn.example.test/private/asset-123/output.webp?token=secret#fragment");
  assert.equal(result.origin, "https://cdn.example.test");
  assert.equal(result.display, "https://cdn.example.test/….webp");
  assert.equal(result.display.includes("secret"), false);
  assert.equal(result.display.includes("asset-123"), false);
});

test("scanText extracts evidence without retaining identifier values", () => {
  const scan = scanText(JSON.stringify({
    job_id: "sensitive-job-value",
    thumbnail_url: "https://cdn.example.test/t.png?sig=sensitive",
    error: "content policy violation",
  }));
  assert.deepEqual(scan.idFields, ["job_id"]);
  assert.equal(scan.urlReferences[0].field, "thumbnail_url");
  assert.ok(scan.denialCodes.includes("content-violation"));
  assert.equal(JSON.stringify(scan).includes("sensitive-job-value"), false);
});

test("scanText recognizes the Chinese third-party similarity refusal", () => {
  const scan = scanText(
    "非常抱歉，生成的图片可能违反了关于与第三方内容相似性的防护限制。如果你认为此判断有误，请重试或修改提示语。",
  );
  assert.ok(scan.denialCodes.includes("zh-third-party-similarity"));
  assert.ok(scan.denialCodes.includes("zh-guardrail-limit"));
});

test("keyword-only mode recognizes only user-configured refusal text", () => {
  const match = scanText("系统回复：非常抱歉，无法完成。", {
    keywordOnly: true,
    denialKeywords: ["非常抱歉"],
  });
  const noMatch = scanText("This request was blocked by the safety policy.", {
    keywordOnly: true,
    denialKeywords: ["非常抱歉"],
  });
  assert.deepEqual(match.denialCodes, ["custom-keyword-1"]);
  assert.deepEqual(noMatch.denialCodes, []);
});

test("keyword counting supports a baseline with repeated prior refusals", () => {
  assert.deepEqual(
    countKeywordOccurrences("非常抱歉。旧消息。非常抱歉。", ["非常抱歉", "无法生成"]),
    [2, 0],
  );
});

test("base64 byte estimation handles padding", () => {
  assert.equal(estimateBase64Bytes("TQ=="), 1);
  assert.equal(estimateBase64Bytes("TWE="), 2);
  assert.equal(estimateBase64Bytes("TWFu"), 3);
});

test("image candidate scoring requires multiple independent hints", () => {
  const weak = scoreImageCandidate({ mime: "image/png", status: 200, bytes: 400, resourceType: "Image" });
  const strong = scoreImageCandidate({
    mime: "image/png",
    status: 200,
    bytes: 100000,
    resourceType: "Image",
    verifiedBody: true,
  });
  assert.equal(weak.candidate, false);
  assert.equal(strong.candidate, true);
});

test("classification returns L0 for denial without client evidence", () => {
  assert.equal(classifyRun(runWith([])).level, "L0");
});

test("classification returns L1 for identifiers before denial", () => {
  const run = runWith([{ timeMs: 200, category: "job-identifier" }]);
  assert.equal(classifyRun(run).level, "L1");
});

test("classification returns L2 for an image capability before denial", () => {
  const run = runWith([{ timeMs: 400, category: "capability-reference" }]);
  assert.equal(classifyRun(run).level, "L2");
});

test("classification returns L3 for candidate image bytes before denial", () => {
  const run = runWith([{ timeMs: 800, category: "delivery-bytes", strongConfidence: true }]);
  const result = classifyRun(run);
  assert.equal(result.level, "L3");
  assert.equal(result.confidence, "high");
});

test("bytes observed after denial do not raise the level", () => {
  const run = runWith([{ timeMs: 1500, category: "delivery-bytes", strongConfidence: true }]);
  assert.equal(classifyRun(run).level, "L0");
});

test("ignored evidence does not affect classification", () => {
  const run = runWith([{ timeMs: 800, category: "delivery-bytes", strongConfidence: true, ignored: true }]);
  assert.equal(classifyRun(run).level, "L0");
});

test("manual denial time overrides an earlier heuristic match", () => {
  const run = runWith([{ timeMs: 800, category: "delivery-bytes", strongConfidence: true }], 100);
  run.manualDenialAtMs = 1000;
  assert.equal(classifyRun(run).level, "L3");
});

test("pre-existing denial requests a rerun instead of claiming L0", () => {
  const run = runWith([]);
  run.preExistingDenial = true;
  const result = classifyRun(run);
  assert.equal(result.level, "!");
  assert.match(result.title, /已识别/);
});

test("multiple denial clusters invalidate single-attempt attribution", () => {
  const run = runWith([
    { timeMs: 1000, category: "denial" },
    { timeMs: 5000, category: "denial" },
  ], 1000);
  const result = classifyRun(run);
  assert.equal(result.level, "!");
  assert.match(result.title, /多次拒绝/);
});
