export const SCHEMA_VERSION = 2;

export const DEFAULT_DENIAL_KEYWORDS = Object.freeze(["非常抱歉"]);

export const DEFAULT_SETTINGS = Object.freeze({
  minImageBytes: 16 * 1024,
  minRenderedDimension: 96,
  maxTextScanBytes: 2 * 1024 * 1024,
  maxHashBytes: 8 * 1024 * 1024,
  denialKeywords: DEFAULT_DENIAL_KEYWORDS,
  keywordOnly: true,
  captureImages: false,
});

const DENIAL_RULES = [
  ["content-violation", /\bcontent[_\s-]?(?:policy[_\s-]?)?violation\b/i],
  ["policy-block", /\b(?:blocked|rejected|denied)\b.{0,40}\b(?:policy|safety|moderation|content)\b/i],
  ["cannot-generate", /\b(?:cannot|can't|unable to|won't)\s+(?:create|generate|help with)\b/i],
  ["not-allowed", /\bnot\s+allowed\b.{0,40}\b(?:policy|content|request|image)\b/i],
  ["moderation-block", /\b(?:moderation|safety)[_\s-]?(?:block|reject|deny|filter)/i],
  ["zh-policy-violation", /(?:违反|不符合|触犯).{0,24}(?:内容|安全|使用)?(?:政策|规则|准则)/],
  ["zh-third-party-similarity", /(?:第三方内容|内容相似性|与第三方内容相似).{0,32}(?:防护|限制)/],
  ["zh-guardrail-limit", /(?:可能)?违反.{0,48}(?:防护限制|相似性限制)/],
  ["zh-generation-block", /(?:无法|不能|不予|拒绝).{0,16}(?:生成|创建|提供)(?:该|此|这)?(?:图像|图片|内容)?/],
  ["zh-content-block", /(?:内容|请求|图像|图片).{0,16}(?:违规|被阻止|被拒绝)/],
];

const URL_FIELD_RE = /["']?(image_url|thumbnail_url|preview_url|asset_url|download_url|output_url|signed_url|media_url)["']?\s*[:=]\s*["']([^"'\s]{4,})["']/gi;
const ID_FIELD_RE = /["']?(job_id|asset_id|file_id|generation_id|task_id)["']?\s*[:=]\s*["']?([A-Za-z0-9._:-]{4,})/gi;
const DATA_IMAGE_RE = /data:image\/([a-z0-9.+-]+);base64,([A-Za-z0-9+/_=-]{128,})/gi;
const BARE_IMAGE_MAGIC_RE = /(?:iVBORw0KGgo|\/9j\/|UklGR[A-Za-z0-9+/_=-]{8,}WEBP|AAAA(?:G|I)[A-Za-z0-9+/_=-]{2,}Z0eX(?:Bhdmlm|Bhdmlj))/g;

const IMAGE_EXT_RE = /\.(?:avif|bmp|gif|heic|heif|jpe?g|png|webp)$/i;
const OUTPUT_URL_RE = /(?:^|[/_.-])(?:asset|generation|image|img|media|output|preview|render|result|thumbnail)(?:[/_.-]|$)/i;

export function fingerprint(value) {
  const text = String(value ?? "");
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

export function sanitizeUrl(rawValue, baseValue) {
  const raw = String(rawValue ?? "");
  const id = `url-${fingerprint(raw)}`;

  if (!raw) {
    return { id, display: "(empty URL)", scheme: "unknown", origin: "" };
  }

  if (/^data:/i.test(raw)) {
    const mime = raw.match(/^data:([^;,]+)/i)?.[1] || "unknown";
    return {
      id,
      display: `data:${mime};… (${raw.length} chars)`,
      scheme: "data",
      origin: "data:",
      mimeHint: mime,
      rawLength: raw.length,
    };
  }

  if (/^blob:/i.test(raw)) {
    let origin = "blob:";
    try {
      origin = new URL(raw.slice(5)).origin;
    } catch {
      // Keep the generic origin; never persist the opaque blob identifier.
    }
    return {
      id,
      display: `blob:${origin}/…`,
      scheme: "blob",
      origin,
    };
  }

  try {
    const parsed = baseValue ? new URL(raw, baseValue) : new URL(raw);
    const extension = parsed.pathname.match(/\.([A-Za-z0-9]{2,6})$/)?.[1]?.toLowerCase();
    const suffix = extension ? `….${extension}` : "…";
    return {
      id,
      display: `${parsed.origin}/${suffix}`,
      scheme: parsed.protocol.replace(":", ""),
      origin: parsed.origin,
      extension: extension || "",
    };
  } catch {
    return {
      id,
      display: `opaque:… (${raw.length} chars)`,
      scheme: "opaque",
      origin: "",
      rawLength: raw.length,
    };
  }
}

export function looksLikeImageMime(mime = "") {
  return /^image\//i.test(String(mime));
}

export function looksLikeTextMime(mime = "") {
  const normalized = String(mime).toLowerCase().split(";", 1)[0].trim();
  return (
    normalized === "application/json" ||
    normalized.endsWith("+json") ||
    normalized === "application/problem+json" ||
    normalized === "application/graphql-response+json" ||
    normalized === "text/plain" ||
    normalized === "text/event-stream"
  );
}

export function looksLikeImageUrl(rawUrl = "") {
  try {
    return IMAGE_EXT_RE.test(new URL(String(rawUrl)).pathname);
  } catch {
    return IMAGE_EXT_RE.test(String(rawUrl).split(/[?#]/, 1)[0]);
  }
}

export function looksLikeOutputUrl(rawUrl = "") {
  try {
    return OUTPUT_URL_RE.test(new URL(String(rawUrl)).pathname);
  } catch {
    return OUTPUT_URL_RE.test(String(rawUrl).split(/[?#]/, 1)[0]);
  }
}

export function estimateBase64Bytes(base64 = "") {
  const normalized = String(base64).replace(/\s+/g, "");
  if (!normalized) return 0;
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - padding);
}

export function imageMagicFromBase64(base64 = "") {
  const value = String(base64).replace(/\s+/g, "");
  if (value.startsWith("iVBORw0KGgo")) return "png";
  if (value.startsWith("/9j/")) return "jpeg";
  if (value.startsWith("R0lGOD")) return "gif";
  if (value.startsWith("UklGR") && value.slice(12, 24).includes("V0VCUA")) return "webp";
  if (/^AAAA(?:G|I).{0,16}Z0eX(?:Bhdmlm|Bhdmlj)/.test(value)) return "avif";
  return "";
}

export function countKeywordOccurrences(text, keywords = []) {
  const value = String(text ?? "").toLocaleLowerCase();
  return keywords.slice(0, 12).map((keyword) => {
    const needle = String(keyword || "").trim().toLocaleLowerCase();
    if (!needle) return 0;
    let count = 0;
    let offset = 0;
    while (offset < value.length) {
      const index = value.indexOf(needle, offset);
      if (index < 0) break;
      count += 1;
      offset = index + Math.max(1, needle.length);
    }
    return count;
  });
}

export function scanText(text, limits = {}) {
  const maxCharacters = Math.max(1024, limits.maxCharacters || DEFAULT_SETTINGS.maxTextScanBytes);
  const value = String(text ?? "").slice(0, maxCharacters);
  const denialCodes = [];

  if (!limits.keywordOnly) {
    for (const [code, pattern] of DENIAL_RULES) {
      if (pattern.test(value)) denialCodes.push(code);
    }
  }

  const denialKeywords = Array.isArray(limits.denialKeywords) ? limits.denialKeywords : [];
  countKeywordOccurrences(value, denialKeywords).forEach((count, index) => {
    if (count > 0) {
      denialCodes.push(`custom-keyword-${index + 1}`);
    }
  });

  if (limits.keywordOnly && denialKeywords.length === 0) {
    for (const [code, pattern] of DENIAL_RULES) {
      if (pattern.test(value)) denialCodes.push(code);
    }
  }

  const urlReferences = [];
  URL_FIELD_RE.lastIndex = 0;
  for (let match = URL_FIELD_RE.exec(value); match && urlReferences.length < 12; match = URL_FIELD_RE.exec(value)) {
    urlReferences.push({ field: match[1].toLowerCase(), value: match[2].replace(/\\\//g, "/") });
  }

  const idFields = [];
  ID_FIELD_RE.lastIndex = 0;
  for (let match = ID_FIELD_RE.exec(value); match && idFields.length < 12; match = ID_FIELD_RE.exec(value)) {
    idFields.push(match[1].toLowerCase());
  }

  const embeddedImages = [];
  DATA_IMAGE_RE.lastIndex = 0;
  for (let match = DATA_IMAGE_RE.exec(value); match && embeddedImages.length < 4; match = DATA_IMAGE_RE.exec(value)) {
    embeddedImages.push({
      format: match[1].toLowerCase(),
      bytes: estimateBase64Bytes(match[2]),
      source: "data-uri",
    });
  }

  if (embeddedImages.length === 0) {
    BARE_IMAGE_MAGIC_RE.lastIndex = 0;
    for (let match = BARE_IMAGE_MAGIC_RE.exec(value); match && embeddedImages.length < 4; match = BARE_IMAGE_MAGIC_RE.exec(value)) {
      const format = imageMagicFromBase64(match[0]);
      embeddedImages.push({ format: format || "image-signature", bytes: 0, source: "base64-signature" });
    }
  }

  return {
    denialCodes: [...new Set(denialCodes)],
    urlReferences,
    idFields: [...new Set(idFields)],
    embeddedImages,
    truncated: String(text ?? "").length > value.length,
    scannedCharacters: value.length,
  };
}

export function scoreImageCandidate(metadata, settings = DEFAULT_SETTINGS) {
  const normalized = { ...DEFAULT_SETTINGS, ...settings };
  const reasons = [];
  let score = 0;

  if (looksLikeImageMime(metadata.mime)) {
    score += 2;
    reasons.push("image MIME");
  }
  if (metadata.status >= 200 && metadata.status < 300) {
    score += 1;
    reasons.push("successful response");
  }
  if ((metadata.bytes || 0) > 0) {
    score += 1;
    reasons.push("non-empty body");
  }
  if ((metadata.bytes || 0) >= normalized.minImageBytes) {
    score += 2;
    reasons.push(`≥${normalized.minImageBytes} bytes`);
  }
  if (["Image", "Fetch", "XHR"].includes(metadata.resourceType)) {
    score += 1;
    reasons.push(metadata.resourceType);
  }
  if (metadata.outputUrlHint) {
    score += 1;
    reasons.push("output-like URL");
  }
  if (metadata.verifiedBody) {
    score += 1;
    reasons.push("response body verified");
  }

  return { score, candidate: score >= 6, reasons };
}

export function resolveDenialTime(run) {
  if (Number.isFinite(run.manualDenialAtMs)) return run.manualDenialAtMs;
  if (Number.isFinite(run.autoDenialAtMs)) return run.autoDenialAtMs;
  return null;
}

export function classifyRun(run) {
  if (!run) {
    return {
      level: "—",
      confidence: "none",
      title: "尚未开始",
      explanation: "点击开始审计，然后在目标页面提交一次测试。",
    };
  }

  const denialAtMs = resolveDenialTime(run);
  if (denialAtMs === null) {
    const keywords = run.settings?.denialKeywords?.join(" / ") || "非常抱歉";
    return {
      level: "—",
      confidence: "none",
      title: run.status === "recording" ? "正在等待拒绝判定" : "没有观察到拒绝判定",
      explanation: `正在监听拒绝关键词：${keywords}。也可点击“立即扫描”或手动标记。`,
    };
  }

  if (run.preExistingDenial && !Number.isFinite(run.manualDenialAtMs)) {
    return {
      level: "!",
      confidence: "none",
      title: "已识别页面中的拒绝文本",
      explanation: "该拒绝文本在审计启动时已经存在，因此无法恢复此前的网络时序。请清空记录，在提交生成请求之前重新开始。",
      evidenceEventIds: (run.events || []).filter((event) => event.category === "denial").map((event) => event.id),
    };
  }

  const denialClusters = (run.events || []).filter((event) => event.category === "denial" && !event.ignored);
  if (denialClusters.length > 1 && !Number.isFinite(run.manualDenialAtMs)) {
    return {
      level: "!",
      confidence: "none",
      title: "一次审计中检测到多次拒绝",
      explanation: "多个生成尝试共享同一时间线，图片事件无法可靠归属到某一次尝试。请清空后每次只测试一个提示词。",
      evidenceEventIds: denialClusters.map((event) => event.id),
    };
  }

  const eligible = (run.events || []).filter(
    (event) => !event.ignored && event.category !== "denial" && event.timeMs <= denialAtMs + 250,
  );
  const byteEvents = eligible.filter((event) => event.category === "delivery-bytes" && event.candidate !== false);
  const capabilityEvents = eligible.filter(
    (event) => event.category === "capability-reference" && event.candidate !== false,
  );
  const identifierEvents = eligible.filter(
    (event) => event.category === "job-identifier" && event.candidate !== false,
  );

  if (byteEvents.length > 0) {
    const verified = byteEvents.some((event) => event.strongConfidence);
    return {
      level: "L3",
      confidence: verified ? "high" : "medium",
      title: "检测到拒绝前客户端数据候选",
      explanation: verified
        ? "在拒绝判定前观察到了经响应正文或成功解码确认的图像数据。仍需排除页面无关图片。"
        : "在拒绝判定前观察到了图像字节候选；请核对时间线中的来源、大小和 URL 指纹。",
      evidenceEventIds: byteEvents.map((event) => event.id),
    };
  }

  if (capabilityEvents.length > 0) {
    return {
      level: "L2",
      confidence: "medium",
      title: "检测到拒绝前图片能力引用",
      explanation: "客户端在拒绝前收到或创建了图片/缩略图 URL，但尚未确认图片字节成功到达。",
      evidenceEventIds: capabilityEvents.map((event) => event.id),
    };
  }

  if (identifierEvents.length > 0) {
    return {
      level: "L1",
      confidence: "medium",
      title: "仅检测到任务或资产标识符",
      explanation: "这能支持阶段分析，但不能证明图像内容到达客户端。",
      evidenceEventIds: identifierEvents.map((event) => event.id),
    };
  }

  return {
    level: "L0",
    confidence: "medium",
    title: "未观察到客户端图片证据",
    explanation: "本次记录只有拒绝信号。L0 表示未发现证据，不等于证明服务器没有生成图片。",
    evidenceEventIds: [],
  };
}

export function makeExport(run) {
  if (!run) return null;
  const {
    pendingResponses: _pendingResponses,
    pendingWebSockets: _pendingWebSockets,
    contentFrameIds: _contentFrameIds,
    ...publicRun
  } = run;
  return {
    exportSchema: "gateleak-audit/v1",
    exportedAt: new Date().toISOString(),
    ...publicRun,
    classification: classifyRun(run),
  };
}
