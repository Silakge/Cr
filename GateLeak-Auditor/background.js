import {
  DEFAULT_SETTINGS,
  SCHEMA_VERSION,
  classifyRun,
  countKeywordOccurrences,
  estimateBase64Bytes,
  imageMagicFromBase64,
  looksLikeImageMime,
  looksLikeImageUrl,
  looksLikeOutputUrl,
  looksLikeTextMime,
  makeExport,
  sanitizeUrl,
  scanText,
  scoreImageCandidate,
} from "./lib/core.js";

const STORAGE_KEY = "gateleakCurrentRun";
const CAPTURE_STORAGE_KEY = "gateleakImageCaptures";
const MAX_EVENTS = 1200;
const MAX_PENDING_RESPONSES = 240;
const MAX_CAPTURE_COUNT = 3;
const MAX_CAPTURE_BYTES = 3 * 1024 * 1024;
const MAX_CAPTURE_TOTAL_BYTES = 5 * 1024 * 1024;

let runCache = null;
let operationChain = Promise.resolve();
const intentionalDetaches = new Set();

function enqueue(operation) {
  operationChain = operationChain.then(operation, operation);
  return operationChain;
}

async function loadRun() {
  if (runCache) return runCache;
  const stored = await chrome.storage.session.get(STORAGE_KEY);
  runCache = stored[STORAGE_KEY] || null;
  return runCache;
}

async function persistRun(run) {
  run.classification = classifyRun(run);
  runCache = run;
  await chrome.storage.session.set({ [STORAGE_KEY]: run });
  await updateBadge(run);
}

async function removeRun() {
  runCache = null;
  await chrome.storage.session.remove(STORAGE_KEY);
  await chrome.action.setBadgeText({ text: "" });
}

async function loadCaptures() {
  const stored = await chrome.storage.session.get(CAPTURE_STORAGE_KEY);
  return stored[CAPTURE_STORAGE_KEY] || null;
}

async function removeCaptures() {
  await chrome.storage.session.remove(CAPTURE_STORAGE_KEY);
}

function addWarning(run, warning) {
  run.warnings ||= [];
  if (!run.warnings.includes(warning)) run.warnings.push(warning);
  run.warnings = run.warnings.slice(-20);
}

function appendEvent(run, event) {
  const epochMs = Number.isFinite(event.epochMs) ? event.epochMs : Date.now();
  if (event.category === "denial" && event.source !== "manual") {
    const previousDenials = run.events.filter((entry) => entry.category === "denial" && entry.source !== "manual");
    const previous = previousDenials.at(-1);
    if (previous && Math.abs(epochMs - previous.epochMs) <= 1000) {
      previous.details ||= {};
      previous.details.channels = [...new Set([
        ...(previous.details.channels || [previous.source]),
        event.source || "system",
      ])];
      previous.details.rules = [...new Set([
        ...(previous.details.rules || []),
        ...(event.details?.rules || []),
      ])];
      previous.details.corroborated = previous.details.channels.length > 1;
      return previous;
    }
    if (previousDenials.length > 0) {
      addWarning(run, "检测到多次独立拒绝；为保证时序归因，请每次审计只提交一个生成任务。");
      event.details = { ...(event.details || {}), attemptIndex: previousDenials.length + 1 };
    } else {
      event.details = { ...(event.details || {}), attemptIndex: 1 };
    }
  }
  const normalized = {
    id: event.id || `evt-${run.nextEventId++}`,
    epochMs,
    timeMs: Math.max(0, Math.round(epochMs - run.startedEpochMs)),
    source: event.source || "system",
    kind: event.kind || "observation",
    category: event.category || "informational",
    candidate: event.candidate,
    strongConfidence: Boolean(event.strongConfidence),
    ignored: false,
    details: event.details || {},
  };

  if (normalized.category === "denial" && normalized.source !== "manual") {
    if (!Number.isFinite(run.autoDenialAtMs) || normalized.timeMs < run.autoDenialAtMs) {
      run.autoDenialAtMs = normalized.timeMs;
    }
  }

  run.events.push(normalized);
  if (run.events.length > MAX_EVENTS) {
    run.events.splice(0, run.events.length - MAX_EVENTS);
    addWarning(run, `时间线已限制为最近 ${MAX_EVENTS} 条事件。`);
  }
  return normalized;
}

function normalizeSettings(settings = {}) {
  const rawKeywords = Array.isArray(settings.denialKeywords)
    ? settings.denialKeywords
    : String(settings.denialKeywords || "非常抱歉").split(/[|\n]/);
  const denialKeywords = [...new Set(
    rawKeywords.map((keyword) => String(keyword).trim().slice(0, 80)).filter(Boolean),
  )].slice(0, 12);
  return {
    ...DEFAULT_SETTINGS,
    minImageBytes: Math.min(
      10 * 1024 * 1024,
      Math.max(512, Number(settings.minImageBytes) || DEFAULT_SETTINGS.minImageBytes),
    ),
    minRenderedDimension: Math.min(
      4096,
      Math.max(1, Number(settings.minRenderedDimension) || DEFAULT_SETTINGS.minRenderedDimension),
    ),
    denialKeywords: denialKeywords.length ? denialKeywords : ["非常抱歉"],
    keywordOnly: settings.keywordOnly !== false,
    captureImages: settings.captureImages === true,
  };
}

function textScanOptions(run) {
  return {
    maxCharacters: run.settings.maxTextScanBytes,
    denialKeywords: run.settings.denialKeywords,
    keywordOnly: run.settings.keywordOnly,
  };
}

async function sendToContentFrames(run, message) {
  const frameIds = Array.isArray(run.contentFrameIds) && run.contentFrameIds.length
    ? run.contentFrameIds
    : [0];
  for (const frameId of frameIds) {
    try {
      await chrome.tabs.sendMessage(run.tabId, message, { frameId });
    } catch {
      // A frame may have navigated or become cross-origin.
    }
  }
}

async function injectDomObservers(run) {
  const results = [];
  const mainResult = await chrome.scripting.executeScript({
    target: { tabId: run.tabId },
    files: ["content.js"],
    injectImmediately: true,
  });
  if (Array.isArray(mainResult)) results.push(...mainResult);

  try {
    const allFrameResults = await chrome.scripting.executeScript({
      target: { tabId: run.tabId, allFrames: true },
      files: ["content.js"],
      injectImmediately: true,
    });
    if (Array.isArray(allFrameResults)) results.push(...allFrameResults);
  } catch {
    // The top frame is already covered; inaccessible child frames are optional.
  }

  run.contentFrameIds = [...new Set(results.map((result) => result.frameId).filter(Number.isInteger))];
  if (run.contentFrameIds.length === 0) run.contentFrameIds = [0];
  await sendToContentFrames(run, {
    type: "GATELEAK_START",
    settings: {
      denialKeywords: run.settings.denialKeywords,
      keywordOnly: run.settings.keywordOnly,
    },
  });
}

async function directPageTextScan(run, { preExisting = false, source = "manual-scan" } = {}) {
  let results = [];
  try {
    results = await chrome.scripting.executeScript({
      target: { tabId: run.tabId, allFrames: true },
      func: () => ({
        text: String(document.body?.textContent || document.documentElement?.textContent || "").slice(-300000),
        frameOrigin: location.origin,
        epochMs: Date.now(),
      }),
      injectImmediately: true,
    });
  } catch {
    try {
      results = await chrome.scripting.executeScript({
        target: { tabId: run.tabId },
        func: () => ({
          text: String(document.body?.textContent || document.documentElement?.textContent || "").slice(-300000),
          frameOrigin: location.origin,
          epochMs: Date.now(),
        }),
        injectImmediately: true,
      });
    } catch {
      addWarning(run, "直接页面文本扫描失败；仍可使用手动拒绝标记。");
      return false;
    }
  }

  const aggregateCounts = run.settings.denialKeywords.map(() => 0);
  const builtinCodes = new Set();
  let firstMatch = null;
  for (const frameResult of results || []) {
    const value = frameResult?.result;
    if (!value?.text) continue;
    const counts = countKeywordOccurrences(value.text, run.settings.denialKeywords);
    counts.forEach((count, index) => { aggregateCounts[index] += count; });
    const scan = scanText(value.text, textScanOptions(run));
    for (const code of scan.denialCodes.filter((code) => !code.startsWith("custom-keyword-"))) {
      builtinCodes.add(code);
    }
    if (!firstMatch && (counts.some((count) => count > 0) || builtinCodes.size > 0)) {
      firstMatch = { frameResult, value };
    }
  }

  if (preExisting) {
    run.keywordBaselineCounts = aggregateCounts;
    if (aggregateCounts.some((count) => count > 0)) {
      appendEvent(run, {
        source: "dom-scan",
        kind: "keyword-baseline-established",
        category: "informational",
        candidate: false,
        details: { counts: aggregateCounts, detectionSource: source },
      });
    }
    return false;
  }

  const baseline = Array.isArray(run.keywordBaselineCounts)
    ? run.keywordBaselineCounts
    : run.settings.denialKeywords.map(() => 0);
  const increasedCodes = aggregateCounts
    .map((count, index) => count > (baseline[index] || 0) ? `custom-keyword-${index + 1}` : "")
    .filter(Boolean);
  const denialCodes = [...increasedCodes, ...builtinCodes];
  if (denialCodes.length > 0 && !(run.events || []).some((event) => event.category === "denial")) {
    appendEvent(run, {
      epochMs: Number.isFinite(firstMatch?.value?.epochMs) ? firstMatch.value.epochMs : Date.now(),
      source: "dom-scan",
      kind: "automatic-denial",
      category: "denial",
      candidate: true,
      details: {
        rules: denialCodes,
        detectionSource: source,
        frameId: Number.isInteger(firstMatch?.frameResult?.frameId) ? firstMatch.frameResult.frameId : 0,
        frameOrigin: sanitizeUrl(firstMatch?.value?.frameOrigin || "").origin,
        baselineCounts: baseline,
        currentCounts: aggregateCounts,
      },
    });
    return true;
  }
  return false;
}

async function updateBadge(run) {
  if (!run) {
    await chrome.action.setBadgeText({ text: "" });
    return;
  }

  const level = run.classification?.level;
  const text = level && level !== "—" ? level : run.status === "recording" ? "REC" : "";
  const colors = {
    REC: "#b91c1c",
    L0: "#475569",
    L1: "#2563eb",
    L2: "#d97706",
    L3: "#7e22ce",
  };
  await chrome.action.setBadgeBackgroundColor({ color: colors[text] || "#475569" });
  await chrome.action.setBadgeText({ text });
}

function currentDebuggee(run) {
  return { tabId: run.tabId };
}

async function safeDetach(run) {
  if (!run?.tabId) return;
  intentionalDetaches.add(run.tabId);
  try {
    await chrome.debugger.detach(currentDebuggee(run));
  } catch {
    // It may already be detached after navigation, DevTools opening, or tab close.
  }
  setTimeout(() => intentionalDetaches.delete(run.tabId), 2000);
}

async function startAudit(message) {
  const existing = await loadRun();
  if (existing?.status === "recording") {
    await stopAudit("superseded");
  }
  await removeCaptures();

  const tabId = Number(message.tabId);
  if (!Number.isInteger(tabId)) throw new Error("没有可审计的活动标签页。");
  if (/^(?:chrome|edge|about|devtools|chrome-extension):/i.test(String(message.tabUrl || ""))) {
    throw new Error("Chrome 内部页面不允许附加调试器。请切换到目标网页后重试。");
  }

  const debuggee = { tabId };
  await chrome.debugger.attach(debuggee, "1.3");

  const settings = normalizeSettings(message.settings);
  const target = sanitizeUrl(message.tabUrl || "");
  const now = Date.now();
  const run = {
    schemaVersion: SCHEMA_VERSION,
    runId: crypto.randomUUID(),
    tabId,
    targetOrigin: target.origin || target.display,
    status: "recording",
    startedAt: new Date(now).toISOString(),
    startedEpochMs: now,
    stoppedAt: null,
    autoDenialAtMs: null,
    manualDenialAtMs: null,
    settings,
    nextEventId: 1,
    events: [],
    warnings: [],
    pendingResponses: {},
    pendingWebSockets: {},
    contentFrameIds: [],
    domObserverFrames: [],
    preExistingDenial: false,
    keywordBaselineCounts: settings.denialKeywords.map(() => 0),
  };

  try {
    await chrome.debugger.sendCommand(debuggee, "Network.enable", {
      maxTotalBufferSize: 16 * 1024 * 1024,
      maxResourceBufferSize: 8 * 1024 * 1024,
      maxPostDataSize: 0,
    });

    appendEvent(run, {
      epochMs: now,
      source: "system",
      kind: "audit-started",
      details: { targetOrigin: run.targetOrigin },
    });

    try {
      await injectDomObservers(run);
    } catch {
      addWarning(run, "DOM 观察器未能注入；该页面可能限制扩展脚本。网络观察仍会继续。");
    }
    await directPageTextScan(run, { preExisting: true, source: "startup-snapshot" });
    await persistRun(run);
    return run;
  } catch (error) {
    await safeDetach(run);
    throw error;
  }
}

async function stopAudit(reason = "user") {
  const run = await loadRun();
  if (!run) return null;

  if (run.status === "recording") {
    try {
      await sendToContentFrames(run, { type: "GATELEAK_STOP" });
    } catch {
      // The page may have navigated or closed.
    }
    await safeDetach(run);
  }

  run.status = reason === "debugger-detached" ? "interrupted" : "stopped";
  run.stoppedAt = new Date().toISOString();
  appendEvent(run, {
    source: "system",
    kind: "audit-stopped",
    details: { reason },
  });
  await persistRun(run);
  return run;
}

async function manualDenial() {
  const run = await loadRun();
  if (!run || run.status !== "recording") throw new Error("当前没有正在运行的审计。");
  const now = Date.now();
  run.manualDenialAtMs = Math.max(0, Math.round(now - run.startedEpochMs));
  appendEvent(run, {
    epochMs: now,
    source: "manual",
    kind: "manual-denial",
    category: "denial",
    details: { trigger: "user" },
  });
  await persistRun(run);
  return run;
}

async function clearAudit() {
  const run = await loadRun();
  if (run?.status === "recording") await safeDetach(run);
  if (run?.tabId) {
    try {
      await sendToContentFrames(run, { type: "GATELEAK_STOP" });
    } catch {
      // Ignore unavailable content scripts.
    }
  }
  await removeRun();
  await removeCaptures();
}

function parseContentLength(headers = {}) {
  const entry = Object.entries(headers).find(([name]) => name.toLowerCase() === "content-length");
  const value = Number(entry?.[1]);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function shouldTrackResponse(metadata) {
  return metadata.isImage || metadata.scanCandidate;
}

async function onRequestWillBeSent(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;
  const rawUrl = params.request?.url || "";
  const imageLike = params.type === "Image" || looksLikeImageUrl(rawUrl);
  if (!imageLike || !looksLikeOutputUrl(rawUrl)) return;

  const safeUrl = sanitizeUrl(rawUrl);
  appendEvent(run, {
    source: "network",
    kind: "image-request-observed",
    category: "capability-reference",
    candidate: true,
    details: {
      url: safeUrl.display,
      urlId: safeUrl.id,
      resourceType: params.type || "Other",
      note: "客户端发起了输出样式图片请求；尚未确认响应字节。",
    },
  });
  await persistRun(run);
}

async function onResponseReceived(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;

  const response = params.response || {};
  const rawUrl = response.url || "";
  const mime = String(response.mimeType || "").toLowerCase();
  const resourceType = params.type || "Other";
  const isImage = looksLikeImageMime(mime) || resourceType === "Image" || looksLikeImageUrl(rawUrl);
  const scanCandidate = looksLikeTextMime(mime) || ["XHR", "Fetch"].includes(resourceType);
  const safeUrl = sanitizeUrl(rawUrl);

  const metadata = {
    requestId: params.requestId,
    safeUrl,
    baseOrigin: safeUrl.origin,
    mime,
    status: Number(response.status) || 0,
    resourceType,
    isImage,
    scanCandidate,
    outputUrlHint: looksLikeOutputUrl(rawUrl),
    imageUrlHint: looksLikeImageUrl(rawUrl),
    fromDiskCache: Boolean(response.fromDiskCache),
    fromServiceWorker: Boolean(response.fromServiceWorker),
    contentLength: parseContentLength(response.headers),
  };

  if (!shouldTrackResponse(metadata)) return;
  run.pendingResponses[params.requestId] = metadata;

  const pendingIds = Object.keys(run.pendingResponses);
  if (pendingIds.length > MAX_PENDING_RESPONSES) {
    for (const requestId of pendingIds.slice(0, pendingIds.length - MAX_PENDING_RESPONSES)) {
      delete run.pendingResponses[requestId];
    }
    addWarning(run, `待处理响应已限制为最近 ${MAX_PENDING_RESPONSES} 条。`);
  }
  await persistRun(run);
}

async function getResponseBody(run, requestId) {
  try {
    return await chrome.debugger.sendCommand(currentDebuggee(run), "Network.getResponseBody", { requestId });
  } catch {
    return null;
  }
}

function utf8ByteLength(value) {
  return new TextEncoder().encode(String(value)).byteLength;
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

async function hashBody(body, base64Encoded, maxBytes) {
  let bytes;
  try {
    bytes = base64Encoded ? base64ToBytes(body) : new TextEncoder().encode(body);
  } catch {
    return { bytes: base64Encoded ? estimateBase64Bytes(body) : utf8ByteLength(body), sha256: "" };
  }

  if (bytes.byteLength > maxBytes) return { bytes: bytes.byteLength, sha256: "" };
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sha256 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return { bytes: bytes.byteLength, sha256 };
}

function rasterCaptureType(mime, bodyBase64) {
  const normalized = String(mime || "").split(";")[0].trim().toLowerCase();
  const known = {
    "image/png": ["image/png", "png"],
    "image/jpeg": ["image/jpeg", "jpg"],
    "image/webp": ["image/webp", "webp"],
    "image/gif": ["image/gif", "gif"],
    "image/avif": ["image/avif", "avif"],
  };
  if (known[normalized]) return known[normalized];
  const detected = imageMagicFromBase64(bodyBase64);
  const detectedTypes = {
    png: ["image/png", "png"],
    jpeg: ["image/jpeg", "jpg"],
    jpg: ["image/jpeg", "jpg"],
    webp: ["image/webp", "webp"],
    gif: ["image/gif", "gif"],
    avif: ["image/avif", "avif"],
  };
  return detectedTypes[detected] || null;
}

function bodyToBase64(body, base64Encoded) {
  if (base64Encoded) return String(body || "").replace(/\s+/g, "");
  const bytes = new TextEncoder().encode(String(body || ""));
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

async function retainImageCapture(run, event, responseBody, bodyInfo, mime) {
  if (!run.settings.captureImages || !event.candidate || !event.strongConfidence) return;
  if (!responseBody?.body || bodyInfo.bytes <= 0) return;
  if (bodyInfo.bytes > MAX_CAPTURE_BYTES) {
    addWarning(run, `候选图片超过单张 ${MAX_CAPTURE_BYTES.toLocaleString()} bytes 的保留上限，仅记录摘要。`);
    return;
  }

  let base64;
  try {
    base64 = bodyToBase64(responseBody.body, Boolean(responseBody.base64Encoded));
  } catch {
    addWarning(run, "候选图片无法编码为可导出数据，仅记录摘要。");
    return;
  }
  const captureType = rasterCaptureType(mime, base64);
  if (!captureType) return;

  let store = await loadCaptures();
  if (!store || store.runId !== run.runId) {
    store = { runId: run.runId, totalBytes: 0, captures: {} };
  }
  const captures = Object.values(store.captures || {});
  if (captures.length >= MAX_CAPTURE_COUNT || store.totalBytes + bodyInfo.bytes > MAX_CAPTURE_TOTAL_BYTES) {
    addWarning(run, `图片保留已达到 ${MAX_CAPTURE_COUNT} 张或 ${MAX_CAPTURE_TOTAL_BYTES.toLocaleString()} bytes 的会话上限。`);
    return;
  }

  const captureId = `cap-${event.id}`;
  store.captures[captureId] = {
    captureId,
    eventId: event.id,
    mime: captureType[0],
    extension: captureType[1],
    bytes: bodyInfo.bytes,
    sha256: bodyInfo.sha256,
    base64,
    createdAt: new Date().toISOString(),
  };
  store.totalBytes += bodyInfo.bytes;
  try {
    await chrome.storage.session.set({ [CAPTURE_STORAGE_KEY]: store });
  } catch {
    addWarning(run, "浏览器会话存储空间不足，候选图片未保留；审计元数据仍会继续记录。");
    return;
  }
  event.details.captureAvailable = true;
  event.details.captureId = captureId;
  event.details.captureMime = captureType[0];
}

async function getImageCapture(captureId) {
  const run = await loadRun();
  const store = await loadCaptures();
  if (!run || !store || store.runId !== run.runId) throw new Error("图片候选已不存在或不属于当前审计。");
  const capture = store.captures?.[String(captureId || "")];
  if (!capture) throw new Error("找不到该图片候选；它可能已被清空或超过保留上限。");
  return capture;
}

function appendScanEvents(run, scan, context) {
  const epochMs = context.epochMs || Date.now();

  for (const embedded of scan.embeddedImages) {
    appendEvent(run, {
      epochMs,
      source: context.source,
      kind: "embedded-image-bytes",
      category: "delivery-bytes",
      candidate: true,
      strongConfidence: true,
      details: {
        transport: context.transport,
        format: embedded.format,
        bytes: embedded.bytes,
        source: embedded.source,
        endpoint: context.safeUrl?.display || "stream",
        urlId: context.safeUrl?.id || "",
      },
    });
  }

  for (const reference of scan.urlReferences) {
    const safeReference = sanitizeUrl(reference.value, context.baseOrigin);
    appendEvent(run, {
      epochMs,
      source: context.source,
      kind: "asset-url-reference",
      category: "capability-reference",
      candidate: true,
      details: {
        field: reference.field,
        url: safeReference.display,
        urlId: safeReference.id,
        endpoint: context.safeUrl?.display || "stream",
      },
    });
  }

  if (scan.idFields.length > 0) {
    appendEvent(run, {
      epochMs,
      source: context.source,
      kind: "job-or-asset-identifier",
      category: "job-identifier",
      candidate: true,
      details: {
        fields: scan.idFields,
        endpoint: context.safeUrl?.display || "stream",
      },
    });
  }

  if (scan.denialCodes.length > 0) {
    appendEvent(run, {
      epochMs,
      source: context.source,
      kind: "automatic-denial",
      category: "denial",
      candidate: true,
      details: {
        rules: scan.denialCodes,
        endpoint: context.safeUrl?.display || "stream",
      },
    });
  }
}

async function onLoadingFinished(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;

  const metadata = run.pendingResponses[params.requestId];
  if (!metadata) return;
  delete run.pendingResponses[params.requestId];

  const encodedDataLength = Math.max(0, Number(params.encodedDataLength) || 0);
  const expectedSize = metadata.contentLength ?? encodedDataLength;
  const bodyReadLimit = metadata.isImage ? run.settings.maxHashBytes : run.settings.maxTextScanBytes;
  const mayReadBody = expectedSize <= bodyReadLimit;
  const responseBody = mayReadBody ? await getResponseBody(run, params.requestId) : null;
  const epochMs = Date.now();

  if (metadata.isImage) {
    let bodyInfo = { bytes: encodedDataLength, sha256: "" };
    let verifiedBody = false;
    if (responseBody?.body) {
      bodyInfo = await hashBody(
        responseBody.body,
        Boolean(responseBody.base64Encoded),
        run.settings.maxHashBytes,
      );
      verifiedBody = bodyInfo.bytes > 0;
    }

    const scoring = scoreImageCandidate(
      {
        mime: metadata.mime,
        status: metadata.status,
        bytes: bodyInfo.bytes || encodedDataLength,
        resourceType: metadata.resourceType,
        outputUrlHint: metadata.outputUrlHint,
        verifiedBody,
      },
      run.settings,
    );

    const imageEvent = appendEvent(run, {
      epochMs,
      source: "network",
      kind: "image-response-complete",
      category: bodyInfo.bytes > 0 || encodedDataLength > 0 ? "delivery-bytes" : "capability-reference",
      candidate: scoring.candidate,
      strongConfidence: scoring.candidate && verifiedBody,
      details: {
        url: metadata.safeUrl.display,
        urlId: metadata.safeUrl.id,
        mime: metadata.mime,
        status: metadata.status,
        resourceType: metadata.resourceType,
        bytes: bodyInfo.bytes || encodedDataLength,
        transferredBytes: encodedDataLength,
        responseBodyVerified: verifiedBody,
        sha256: bodyInfo.sha256 ? `${bodyInfo.sha256.slice(0, 16)}…` : "",
        fromDiskCache: metadata.fromDiskCache,
        fromServiceWorker: metadata.fromServiceWorker,
        candidateScore: scoring.score,
        candidateReasons: scoring.reasons,
      },
    });
    await retainImageCapture(run, imageEvent, responseBody, bodyInfo, metadata.mime);

    if (responseBody?.body && !responseBody.base64Encoded && looksLikeTextMime(metadata.mime)) {
      const scan = scanText(responseBody.body, textScanOptions(run));
      appendScanEvents(run, scan, {
        epochMs,
        source: "network",
        transport: "http-error-body",
        safeUrl: metadata.safeUrl,
        baseOrigin: metadata.baseOrigin,
      });
    }
  } else if (responseBody?.body) {
    if (responseBody.base64Encoded) {
      const format = imageMagicFromBase64(responseBody.body);
      if (format) {
        const bodyInfo = await hashBody(responseBody.body, true, run.settings.maxHashBytes);
        appendEvent(run, {
          epochMs,
          source: "network",
          kind: "binary-image-response",
          category: "delivery-bytes",
          candidate: true,
          strongConfidence: true,
          details: {
            endpoint: metadata.safeUrl.display,
            urlId: metadata.safeUrl.id,
            format,
            bytes: bodyInfo.bytes,
            sha256: bodyInfo.sha256 ? `${bodyInfo.sha256.slice(0, 16)}…` : "",
          },
        });
      }
    } else {
      const scan = scanText(responseBody.body, textScanOptions(run));
      appendScanEvents(run, scan, {
        epochMs,
        source: "network",
        transport: "http",
        safeUrl: metadata.safeUrl,
        baseOrigin: metadata.baseOrigin,
      });
      if (scan.truncated) addWarning(run, "至少一个文本响应超过扫描上限，仅检查了前部内容。");
    }
  } else if (expectedSize > run.settings.maxTextScanBytes && metadata.scanCandidate) {
    addWarning(run, "至少一个候选文本响应过大，未读取正文。可在设置中提高扫描上限后复测。");
  }

  await persistRun(run);
}

async function onLoadingFailed(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;
  const metadata = run.pendingResponses[params.requestId];
  if (metadata) {
    delete run.pendingResponses[params.requestId];
    appendEvent(run, {
      source: "network",
      kind: "candidate-response-failed",
      category: "informational",
      candidate: false,
      details: {
        url: metadata.safeUrl.display,
        urlId: metadata.safeUrl.id,
        error: String(params.errorText || "loading failed").slice(0, 120),
      },
    });
    await persistRun(run);
  }
}

async function onWebSocketCreated(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;
  run.pendingWebSockets[params.requestId] = sanitizeUrl(params.url || "");
  await persistRun(run);
}

async function onWebSocketFrame(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;
  const frame = params.response || {};
  const safeUrl = run.pendingWebSockets[params.requestId];
  const epochMs = Date.now();

  if (frame.opcode === 1 && typeof frame.payloadData === "string") {
    const scan = scanText(frame.payloadData, textScanOptions(run));
    appendScanEvents(run, scan, {
      epochMs,
      source: "websocket",
      transport: "websocket-text",
      safeUrl,
      baseOrigin: safeUrl?.origin,
    });
  } else if (frame.opcode === 2 && typeof frame.payloadData === "string") {
    const bytes = estimateBase64Bytes(frame.payloadData);
    const format = imageMagicFromBase64(frame.payloadData);
    appendEvent(run, {
      epochMs,
      source: "websocket",
      kind: format ? "websocket-image-frame" : "websocket-binary-frame",
      category: format ? "delivery-bytes" : "binary-observation",
      candidate: Boolean(format),
      strongConfidence: Boolean(format),
      details: {
        endpoint: safeUrl?.display || "websocket",
        urlId: safeUrl?.id || "",
        bytes,
        format: format || "unknown",
      },
    });
  }

  await persistRun(run);
}

async function onEventSourceMessage(source, params) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || source.tabId !== run.tabId) return;
  const safeUrl = run.pendingResponses[params.requestId]?.safeUrl;
  const scan = scanText(params.data || "", textScanOptions(run));
  appendScanEvents(run, scan, {
    epochMs: Date.now(),
    source: "eventsource",
    transport: "sse",
    safeUrl,
    baseOrigin: safeUrl?.origin,
  });
  await persistRun(run);
}

async function handleDomEvent(message, sender) {
  const run = await loadRun();
  if (!run || run.status !== "recording" || sender.tab?.id !== run.tabId) return;
  const observed = message.event || {};
  const epochMs = Number.isFinite(observed.epochMs) ? observed.epochMs : Date.now();

  if (observed.kind === "observer-ready") {
    const frameId = Number.isInteger(sender.frameId) ? sender.frameId : 0;
    run.domObserverFrames ||= [];
    if (!run.domObserverFrames.includes(frameId)) run.domObserverFrames.push(frameId);
    appendEvent(run, {
      epochMs,
      source: "dom",
      kind: "dom-observer-ready",
      category: "informational",
      candidate: false,
      details: {
        frameId,
        observerVersion: observed.observerVersion || "unknown",
        frameOrigin: sanitizeUrl(observed.frameOrigin || "").origin,
        isTopFrame: Boolean(observed.isTopFrame),
      },
    });
  } else if (observed.kind === "keyword-baseline") {
    const counts = Array.isArray(observed.counts) ? observed.counts.map((value) => Math.max(0, Number(value) || 0)) : [];
    run.keywordBaselineCounts = run.keywordBaselineCounts.map(
      (value, index) => Math.max(value || 0, counts[index] || 0),
    );
    appendEvent(run, {
      epochMs,
      source: "dom",
      kind: "keyword-baseline-established",
      category: "informational",
      candidate: false,
      details: {
        counts,
        frameId: Number.isInteger(sender.frameId) ? sender.frameId : 0,
        detectionSource: observed.detectionSource || "snapshot",
      },
    });
  } else if (observed.kind === "denial-text") {
    appendEvent(run, {
      epochMs,
      source: "dom",
      kind: "automatic-denial",
      category: "denial",
      candidate: true,
      details: {
        rules: observed.rules || [],
        detectionSource: observed.detectionSource || "dom",
        frameId: Number.isInteger(sender.frameId) ? sender.frameId : 0,
        preExisting: false,
      },
    });
  } else if (observed.kind === "canvas") {
    appendEvent(run, {
      epochMs,
      source: "dom",
      kind: "canvas-observed",
      category: "informational",
      candidate: false,
      details: { width: observed.width || 0, height: observed.height || 0, action: observed.action || "seen" },
    });
  } else if (observed.url) {
    const safeUrl = sanitizeUrl(observed.url);
    const width = Number(observed.width) || 0;
    const height = Number(observed.height) || 0;
    const decoded = observed.kind === "image-loaded" && width > 0 && height > 0;
    const embedded = safeUrl.scheme === "data";
    const blobDecoded = safeUrl.scheme === "blob" && decoded;
    const largeEnough = width >= run.settings.minRenderedDimension && height >= run.settings.minRenderedDimension;
    const category = embedded || blobDecoded || decoded ? "delivery-bytes" : "capability-reference";
    const candidate = embedded || blobDecoded || largeEnough || looksLikeOutputUrl(observed.url);

    appendEvent(run, {
      epochMs,
      source: "dom",
      kind: observed.kind || "asset-reference",
      category,
      candidate,
      strongConfidence: embedded || blobDecoded || (decoded && largeEnough),
      details: {
        url: safeUrl.display,
        urlId: safeUrl.id,
        scheme: safeUrl.scheme,
        tag: observed.tag || "",
        width,
        height,
        action: observed.action || "seen",
      },
    });

    if (decoded) {
      for (const event of run.events) {
        if (event.source === "network" && event.details?.urlId === safeUrl.id) {
          event.candidate = true;
          event.strongConfidence = true;
          event.details.domCorroborated = true;
        }
      }
    }
  }

  await persistRun(run);
}

async function scanCurrentPage() {
  const run = await loadRun();
  if (!run || run.status !== "recording") throw new Error("当前没有正在运行的审计。");
  await sendToContentFrames(run, { type: "GATELEAK_SCAN" });
  await directPageTextScan(run, { preExisting: false, source: "manual-scan" });
  await persistRun(run);
  return run;
}

async function toggleEventIgnore(eventId) {
  const run = await loadRun();
  if (!run) return null;
  const event = run.events.find((entry) => entry.id === eventId);
  if (event) event.ignored = !event.ignored;
  await persistRun(run);
  return run;
}

async function handleDebuggerEvent(source, method, params) {
  switch (method) {
    case "Network.requestWillBeSent":
      await onRequestWillBeSent(source, params);
      break;
    case "Network.responseReceived":
      await onResponseReceived(source, params);
      break;
    case "Network.loadingFinished":
      await onLoadingFinished(source, params);
      break;
    case "Network.loadingFailed":
      await onLoadingFailed(source, params);
      break;
    case "Network.webSocketCreated":
      await onWebSocketCreated(source, params);
      break;
    case "Network.webSocketFrameReceived":
      await onWebSocketFrame(source, params);
      break;
    case "Network.eventSourceMessageReceived":
      await onEventSourceMessage(source, params);
      break;
    default:
      break;
  }
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  enqueue(() => handleDebuggerEvent(source, method, params)).catch(() => {});
});

chrome.debugger.onDetach.addListener((source, reason) => {
  enqueue(async () => {
    if (intentionalDetaches.delete(source.tabId)) return;
    const run = await loadRun();
    if (!run || run.tabId !== source.tabId || run.status !== "recording") return;
    addWarning(run, `调试会话被浏览器终止：${reason}。打开 DevTools 会触发这种情况。`);
    run.status = "interrupted";
    run.stoppedAt = new Date().toISOString();
    appendEvent(run, {
      source: "system",
      kind: "debugger-detached",
      details: { reason },
    });
    await persistRun(run);
  }).catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  enqueue(async () => {
    switch (message?.type) {
      case "START_AUDIT":
        return { ok: true, run: await startAudit(message) };
      case "STOP_AUDIT":
        return { ok: true, run: await stopAudit("user") };
      case "CLEAR_AUDIT":
        await clearAudit();
        return { ok: true };
      case "MANUAL_DENIAL":
        return { ok: true, run: await manualDenial() };
      case "SCAN_PAGE":
        return { ok: true, run: await scanCurrentPage() };
      case "GET_AUDIT": {
        const run = await loadRun();
        if (run) run.classification = classifyRun(run);
        return { ok: true, run };
      }
      case "EXPORT_AUDIT":
        return { ok: true, export: makeExport(await loadRun()) };
      case "GET_IMAGE_CAPTURE":
        return { ok: true, capture: await getImageCapture(message.captureId) };
      case "TOGGLE_EVENT_IGNORE":
        return { ok: true, run: await toggleEventIgnore(message.eventId) };
      case "DOM_EVENT":
        await handleDomEvent(message, sender);
        return { ok: true };
      default:
        return { ok: false, error: "Unknown message." };
    }
  })
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));
  return true;
});

chrome.commands.onCommand.addListener((command) => {
  if (command !== "mark-denial") return;
  enqueue(() => manualDenial()).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  enqueue(async () => {
    const run = await loadRun();
    if (!run || run.tabId !== tabId || run.status !== "recording") return;
    run.status = "interrupted";
    run.stoppedAt = new Date().toISOString();
    addWarning(run, "目标标签页在审计期间关闭。");
    await persistRun(run);
  }).catch(() => {});
});

loadRun().then(updateBadge).catch(() => {});
