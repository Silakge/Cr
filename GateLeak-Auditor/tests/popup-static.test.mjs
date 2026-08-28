import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const popupHtml = await readFile(new URL("../popup.html", import.meta.url), "utf8");
const popupJs = await readFile(new URL("../popup.js", import.meta.url), "utf8");
const popupCss = await readFile(new URL("../popup.css", import.meta.url), "utf8");

test("popup exposes a prominent retained-image export area", () => {
  assert.match(popupHtml, /id="captureSection"/);
  assert.match(popupHtml, /id="captureButtons"/);
  assert.match(popupJs, /renderCapturedImages\(run\)/);
  assert.match(popupJs, /导出候选图片/);
  assert.match(popupCss, /\.captureExportButton/);
});

test("timeline actions wrap below event details instead of clipping on the right", () => {
  assert.match(popupCss, /grid-template-columns:\s*58px minmax\(0, 1fr\)/);
  assert.match(popupCss, /\.eventActions\s*\{[^}]*grid-column:\s*2/s);
});
