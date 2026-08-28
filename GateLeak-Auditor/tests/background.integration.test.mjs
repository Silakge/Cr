import test from "node:test";
import assert from "node:assert/strict";

const storage = new Map();
const listeners = {
  debuggerEvent: [],
  debuggerDetach: [],
  runtimeMessage: [],
  command: [],
  tabRemoved: [],
};
const responseBodies = new Map();
let executeScriptHandler = async () => undefined;

globalThis.chrome = {
  storage: {
    session: {
      async get(key) { return { [key]: storage.get(key) }; },
      async set(values) { for (const [key, value] of Object.entries(values)) storage.set(key, structuredClone(value)); },
      async remove(key) { storage.delete(key); },
    },
  },
  action: {
    async setBadgeText() {},
    async setBadgeBackgroundColor() {},
  },
  debugger: {
    async attach() {},
    async detach() {},
    async sendCommand(_debuggee, method, params) {
      if (method === "Network.getResponseBody") return responseBodies.get(params.requestId) || null;
      return {};
    },
    onEvent: { addListener(listener) { listeners.debuggerEvent.push(listener); } },
    onDetach: { addListener(listener) { listeners.debuggerDetach.push(listener); } },
  },
  scripting: { async executeScript(injection) { return executeScriptHandler(injection); } },
  tabs: {
    async sendMessage() { return {}; },
    onRemoved: { addListener(listener) { listeners.tabRemoved.push(listener); } },
  },
  runtime: {
    onMessage: { addListener(listener) { listeners.runtimeMessage.push(listener); } },
  },
  commands: { onCommand: { addListener(listener) { listeners.command.push(listener); } } },
};

await import("../background.js");

async function sendMessage(message, sender = {}) {
  const listener = listeners.runtimeMessage[0];
  return new Promise((resolve) => listener(message, sender, resolve));
}

async function flushQueue() {
  for (let index = 0; index < 8; index += 1) await new Promise((resolve) => setImmediate(resolve));
}

test("background correlates a verified image response before a DOM denial as L3", async () => {
  const started = await sendMessage({
    type: "START_AUDIT",
    tabId: 7,
    tabUrl: "https://generator.example.test/create?session=secret",
    settings: { minImageBytes: 4096, captureImages: true },
  });
  assert.equal(started.ok, true);

  const imageBytes = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.alloc(20_000),
  ]);
  responseBodies.set("image-request", { body: imageBytes.toString("base64"), base64Encoded: true });

  listeners.debuggerEvent[0](
    { tabId: 7 },
    "Network.responseReceived",
    {
      requestId: "image-request",
      type: "Image",
      response: {
        url: "https://cdn.example.test/private/result.png?token=must-not-persist",
        mimeType: "image/png",
        status: 200,
        headers: { "content-length": String(imageBytes.length) },
      },
    },
  );
  listeners.debuggerEvent[0](
    { tabId: 7 },
    "Network.loadingFinished",
    { requestId: "image-request", encodedDataLength: imageBytes.length },
  );
  await flushQueue();

  await sendMessage(
    { type: "DOM_EVENT", event: { kind: "denial-text", rules: ["content-violation"], epochMs: Date.now() } },
    { tab: { id: 7 } },
  );
  listeners.debuggerEvent[0](
    { tabId: 7 },
    "Network.webSocketFrameReceived",
    { requestId: "socket-1", response: { opcode: 1, payloadData: "非常抱歉，该请求被拒绝。" } },
  );
  await flushQueue();
  const result = await sendMessage({ type: "GET_AUDIT" });
  assert.equal(result.run.classification.level, "L3");
  assert.equal(result.run.classification.confidence, "high");

  const serialized = JSON.stringify(result.run);
  assert.equal(serialized.includes("must-not-persist"), false);
  assert.equal(serialized.includes(imageBytes.toString("base64").slice(0, 32)), false);
  assert.ok(result.run.events.some((event) => event.details?.responseBodyVerified));
  const capturedEvent = result.run.events.find((event) => event.details?.captureAvailable);
  assert.ok(capturedEvent);
  const captured = await sendMessage({
    type: "GET_IMAGE_CAPTURE",
    captureId: capturedEvent.details.captureId,
  });
  assert.equal(captured.ok, true);
  assert.equal(captured.capture.mime, "image/png");
  assert.equal(captured.capture.bytes, imageBytes.length);
  assert.equal(captured.capture.base64, imageBytes.toString("base64"));
  const denialEvents = result.run.events.filter((event) => event.category === "denial");
  assert.equal(denialEvents.length, 1);
  assert.deepEqual(denialEvents[0].details.channels, ["dom", "websocket"]);

  const exported = await sendMessage({ type: "EXPORT_AUDIT" });
  assert.equal("pendingResponses" in exported.export, false);
  assert.equal("pendingWebSockets" in exported.export, false);
  assert.equal(JSON.stringify(exported.export).includes(imageBytes.toString("base64").slice(0, 32)), false);
  await sendMessage({ type: "STOP_AUDIT" });
  assert.equal((await sendMessage({ type: "GET_IMAGE_CAPTURE", captureId: capturedEvent.details.captureId })).ok, true);
  await sendMessage({ type: "CLEAR_AUDIT" });
  assert.equal((await sendMessage({ type: "GET_IMAGE_CAPTURE", captureId: capturedEvent.details.captureId })).ok, false);
});

test("startup snapshot establishes a baseline instead of treating old text as this run's denial", async () => {
  await sendMessage({ type: "CLEAR_AUDIT" });
  executeScriptHandler = async (injection) => {
    if (!injection.func) return [{ frameId: 0 }];
    return [{
      frameId: 0,
      result: {
        text: "非常抱歉，当前请求无法完成。",
        frameOrigin: "https://generator.example.test",
        epochMs: Date.now(),
      },
    }];
  };

  const started = await sendMessage({
    type: "START_AUDIT",
    tabId: 8,
    tabUrl: "https://generator.example.test/create",
    settings: { denialKeywords: ["非常抱歉"], keywordOnly: true },
  });
  assert.equal(started.run.classification.level, "—");
  assert.deepEqual(started.run.keywordBaselineCounts, [1]);
  assert.equal(started.run.events.some((event) => event.category === "denial"), false);
  assert.ok(started.run.events.some((event) => event.kind === "keyword-baseline-established"));

  await sendMessage({ type: "STOP_AUDIT" });
  executeScriptHandler = async () => undefined;
});
