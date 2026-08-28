import { classifyRun, resolveDenialTime } from "./lib/core.js";

const elements = {
  statusBadge: document.querySelector("#statusBadge"),
  minBytes: document.querySelector("#minBytes"),
  denialKeywords: document.querySelector("#denialKeywords"),
  captureImages: document.querySelector("#captureImages"),
  startButton: document.querySelector("#startButton"),
  scanButton: document.querySelector("#scanButton"),
  denialButton: document.querySelector("#denialButton"),
  stopButton: document.querySelector("#stopButton"),
  clearButton: document.querySelector("#clearButton"),
  exportButton: document.querySelector("#exportButton"),
  resultCard: document.querySelector("#resultCard"),
  levelValue: document.querySelector("#levelValue"),
  resultTitle: document.querySelector("#resultTitle"),
  resultExplanation: document.querySelector("#resultExplanation"),
  metaSection: document.querySelector("#metaSection"),
  targetOrigin: document.querySelector("#targetOrigin"),
  observerState: document.querySelector("#observerState"),
  keywordState: document.querySelector("#keywordState"),
  denialTime: document.querySelector("#denialTime"),
  eventCount: document.querySelector("#eventCount"),
  captureSection: document.querySelector("#captureSection"),
  captureCount: document.querySelector("#captureCount"),
  captureButtons: document.querySelector("#captureButtons"),
  warningSection: document.querySelector("#warningSection"),
  warningList: document.querySelector("#warningList"),
  timeline: document.querySelector("#timeline"),
  findingsOnly: document.querySelector("#findingsOnly"),
  errorMessage: document.querySelector("#errorMessage"),
};

let currentRun = null;

async function send(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || "扩展后台没有响应。");
  return response;
}

function setError(message = "") {
  elements.errorMessage.textContent = message;
}

function formatTime(milliseconds) {
  return `+${(Math.max(0, milliseconds) / 1000).toFixed(3)}s`;
}

function eventLabel(event) {
  const labels = {
    "audit-started": "审计开始",
    "audit-stopped": "审计停止",
    "debugger-detached": "调试器断开",
    "automatic-denial": "自动检测到拒绝",
    "dom-observer-ready": "页面监听器就绪",
    "keyword-baseline-established": "已有拒绝文本基线",
    "manual-denial": "手动标记拒绝",
    "image-response-complete": "图片响应完成",
    "image-request-observed": "发起图片请求",
    "candidate-response-failed": "候选响应失败",
    "binary-image-response": "二进制图片响应",
    "embedded-image-bytes": "响应中嵌入图片",
    "asset-url-reference": "图片 URL 引用",
    "job-or-asset-identifier": "任务/资产 ID",
    "websocket-image-frame": "WebSocket 图片帧",
    "websocket-binary-frame": "WebSocket 二进制帧",
    "asset-reference": "DOM 图片引用",
    "asset-removed": "DOM 图片被移除",
    "image-loaded": "浏览器已解码图片",
    "canvas-observed": "Canvas 变化",
  };
  return labels[event.kind] || event.kind;
}

function detailsText(event) {
  const details = event.details || {};
  const fields = [];
  if (details.url) fields.push(details.url);
  if (details.endpoint) fields.push(`端点 ${details.endpoint}`);
  if (details.mime) fields.push(details.mime);
  if (details.status) fields.push(`HTTP ${details.status}`);
  if (Number.isFinite(details.bytes)) fields.push(`${details.bytes.toLocaleString()} bytes`);
  if (details.width && details.height) fields.push(`${details.width}×${details.height}`);
  if (details.format) fields.push(details.format);
  if (details.field) fields.push(`字段 ${details.field}`);
  if (details.fields) fields.push(`字段 ${details.fields.join(", ")}`);
  if (details.rules) fields.push(`规则 ${details.rules.join(", ")}`);
  if (details.channels?.length > 1) fields.push(`通道印证 ${details.channels.join(" + ")}`);
  if (details.attemptIndex) fields.push(`尝试 ${details.attemptIndex}`);
  if (details.counts) fields.push(`基线计数 ${details.counts.join("/")}`);
  if (details.urlId) fields.push(details.urlId);
  if (details.sha256) fields.push(`sha256 ${details.sha256}`);
  if (details.responseBodyVerified) fields.push("正文已验证");
  if (details.observerVersion) fields.push(`observer ${details.observerVersion}`);
  if (details.domCorroborated) fields.push("DOM 已印证");
  if (Number.isFinite(details.candidateScore)) fields.push(`候选分 ${details.candidateScore}`);
  if (details.captureAvailable) fields.push("图片已保留");
  return fields.join(" · ") || event.category;
}

function base64ToBlob(base64, mime) {
  const binary = atob(base64);
  const chunks = [];
  const chunkSize = 64 * 1024;
  for (let offset = 0; offset < binary.length; offset += chunkSize) {
    const part = binary.slice(offset, offset + chunkSize);
    const bytes = new Uint8Array(part.length);
    for (let index = 0; index < part.length; index += 1) bytes[index] = part.charCodeAt(index);
    chunks.push(bytes);
  }
  return new Blob(chunks, { type: mime || "application/octet-stream" });
}

async function exportCapturedImage(event) {
  const response = await send({ type: "GET_IMAGE_CAPTURE", captureId: event.details.captureId });
  const capture = response.capture;
  if (!capture?.base64) throw new Error("图片候选正文不可用。");
  const blob = base64ToBlob(capture.base64, capture.mime);
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `gateleak-${currentRun.runId.slice(0, 8)}-${event.id}.${capture.extension || "bin"}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderCapturedImages(run) {
  const capturedEvents = (run?.events || []).filter((event) => event.details?.captureAvailable);
  elements.captureSection.hidden = capturedEvents.length === 0;
  elements.captureCount.textContent = `${capturedEvents.length} 张`;
  elements.captureButtons.replaceChildren();

  capturedEvents.forEach((event, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "captureExportButton";
    const bytes = Number(event.details?.bytes) || 0;
    const size = bytes >= 1024 * 1024
      ? `${(bytes / (1024 * 1024)).toFixed(2)} MB`
      : `${Math.round(bytes / 1024)} KB`;
    button.textContent = `导出候选图片 ${index + 1} · ${size} · ${formatTime(event.timeMs)}`;
    button.addEventListener("click", async () => {
      setError();
      try {
        await exportCapturedImage(event);
      } catch (error) {
        setError(error.message);
      }
    });
    elements.captureButtons.append(button);
  });
}

function renderTimeline(run) {
  const findingsOnly = elements.findingsOnly.checked;
  const relevantCategories = new Set([
    "denial",
    "delivery-bytes",
    "capability-reference",
    "job-identifier",
    "binary-observation",
  ]);
  const events = (run?.events || []).filter((event) => {
    if (!findingsOnly) return true;
    if (!relevantCategories.has(event.category)) return false;
    if (event.category === "denial") return true;
    return event.candidate !== false;
  });

  elements.timeline.replaceChildren();
  elements.timeline.classList.toggle("empty", events.length === 0);
  if (events.length === 0) {
    elements.timeline.textContent = run?.status === "recording"
      ? "监听中；尚未命中拒绝关键词或图片证据"
      : "暂无证据事件";
    return;
  }

  const denialAt = resolveDenialTime(run);
  for (const event of [...events].reverse()) {
    const row = document.createElement("article");
    row.className = `event${event.ignored ? " ignored" : ""}`;

    const time = document.createElement("div");
    time.className = "eventTime";
    time.textContent = formatTime(event.timeMs);

    const body = document.createElement("div");
    const title = document.createElement("div");
    title.className = "eventTitle";
    const source = document.createElement("span");
    source.className = "eventSource";
    source.textContent = event.source;
    title.append(source, document.createTextNode(eventLabel(event)));
    if (denialAt !== null && event.category !== "denial") {
      title.append(document.createTextNode(event.timeMs <= denialAt + 250 ? " · 拒绝前" : " · 拒绝后"));
    }
    const details = document.createElement("div");
    details.className = "eventDetails";
    details.textContent = detailsText(event);
    body.append(title, details);

    const actions = document.createElement("div");
    actions.className = "eventActions";
    const ignore = document.createElement("label");
    ignore.className = "ignoreLabel";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = event.ignored;
    checkbox.disabled = event.category === "denial" || event.source === "system";
    checkbox.addEventListener("change", async () => {
      try {
        const response = await send({ type: "TOGGLE_EVENT_IGNORE", eventId: event.id });
        currentRun = response.run;
        render(currentRun);
      } catch (error) {
        setError(error.message);
      }
    });
    ignore.append(checkbox, document.createTextNode(" 排除"));
    actions.append(ignore);
    if (event.details?.captureAvailable) {
      const captureButton = document.createElement("button");
      captureButton.type = "button";
      captureButton.className = "captureButton";
      captureButton.textContent = "导出图片";
      captureButton.addEventListener("click", async () => {
        setError();
        try {
          await exportCapturedImage(event);
        } catch (error) {
          setError(error.message);
        }
      });
      actions.append(captureButton);
    }
    row.append(time, body, actions);
    elements.timeline.append(row);
  }
}

function render(run) {
  currentRun = run;
  const classification = classifyRun(run);
  const status = run?.status || "idle";
  const statusLabels = { idle: "空闲", recording: "记录中", stopped: "已停止", interrupted: "已中断" };
  elements.statusBadge.textContent = statusLabels[status] || status;
  elements.statusBadge.className = `status ${status}`;

  elements.resultCard.className = `result level-${classification.level === "—" ? "none" : classification.level}`;
  elements.levelValue.textContent = classification.level;
  elements.resultTitle.textContent = classification.title;
  elements.resultExplanation.textContent = classification.explanation;

  const recording = status === "recording";
  elements.startButton.disabled = recording;
  elements.denialButton.disabled = !recording;
  elements.scanButton.disabled = !recording;
  elements.stopButton.disabled = !recording;
  elements.exportButton.disabled = !run;
  elements.clearButton.disabled = !run;
  elements.minBytes.disabled = recording;
  elements.denialKeywords.disabled = recording;
  elements.captureImages.disabled = recording;

  elements.metaSection.hidden = !run;
  if (run) {
    elements.targetOrigin.textContent = run.targetOrigin || "unknown origin";
    const observerCount = run.domObserverFrames?.length || 0;
    elements.observerState.textContent = observerCount ? `DOM ${observerCount} frame 已连接` : "DOM 尚未连接";
    const baselineCount = (run.keywordBaselineCounts || []).reduce((sum, value) => sum + value, 0);
    elements.keywordState.textContent = `关键词：${run.settings?.denialKeywords?.join(" | ") || "非常抱歉"} · 已忽略旧文本 ${baselineCount}`;
    const denialAt = resolveDenialTime(run);
    elements.denialTime.textContent = denialAt === null ? "尚无拒绝" : `拒绝 ${formatTime(denialAt)}`;
    elements.eventCount.textContent = `${run.events?.length || 0} 个事件`;
    elements.minBytes.value = run.settings?.minImageBytes || 16384;
    elements.denialKeywords.value = run.settings?.denialKeywords?.join(" | ") || "非常抱歉";
    elements.captureImages.checked = run.settings?.captureImages === true;
  }

  const warnings = run?.warnings || [];
  elements.warningSection.hidden = warnings.length === 0;
  elements.warningList.replaceChildren();
  for (const warning of warnings) {
    const item = document.createElement("li");
    item.textContent = warning;
    elements.warningList.append(item);
  }
  renderCapturedImages(run);
  renderTimeline(run);
}

async function refresh() {
  try {
    const response = await send({ type: "GET_AUDIT" });
    render(response.run);
  } catch (error) {
    setError(error.message);
  }
}

elements.startButton.addEventListener("click", async () => {
  setError();
  try {
    if (elements.captureImages.checked) {
      const confirmed = window.confirm("研究模式会在本次浏览器会话中保留最多 3 张候选图片，供你手动导出核验。请仅在获授权的测试中使用。是否继续？");
      if (!confirmed) return;
    }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("无法确定当前标签页。");
    const response = await send({
      type: "START_AUDIT",
      tabId: tab.id,
      tabUrl: tab.url,
      settings: {
        minImageBytes: Number(elements.minBytes.value),
        denialKeywords: elements.denialKeywords.value.split(/[|\n]/).map((value) => value.trim()).filter(Boolean),
        keywordOnly: true,
        captureImages: elements.captureImages.checked,
      },
    });
    render(response.run);
  } catch (error) {
    setError(error.message);
  }
});

elements.scanButton.addEventListener("click", async () => {
  setError();
  try {
    const response = await send({ type: "SCAN_PAGE" });
    render(response.run);
  } catch (error) {
    setError(error.message);
  }
});

elements.denialButton.addEventListener("click", async () => {
  setError();
  try {
    const response = await send({ type: "MANUAL_DENIAL" });
    render(response.run);
  } catch (error) {
    setError(error.message);
  }
});

elements.stopButton.addEventListener("click", async () => {
  setError();
  try {
    const response = await send({ type: "STOP_AUDIT" });
    render(response.run);
  } catch (error) {
    setError(error.message);
  }
});

elements.clearButton.addEventListener("click", async () => {
  setError();
  try {
    await send({ type: "CLEAR_AUDIT" });
    render(null);
  } catch (error) {
    setError(error.message);
  }
});

elements.exportButton.addEventListener("click", async () => {
  setError();
  try {
    const response = await send({ type: "EXPORT_AUDIT" });
    if (!response.export) throw new Error("当前没有可导出的记录。");
    const blob = new Blob([JSON.stringify(response.export, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `gateleak-${response.export.runId}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    setError(error.message);
  }
});

elements.findingsOnly.addEventListener("change", () => renderTimeline(currentRun));

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.gateleakCurrentRun) {
    render(changes.gateleakCurrentRun.newValue || null);
  }
});

refresh();
