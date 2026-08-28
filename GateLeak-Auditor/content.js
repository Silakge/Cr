(() => {
  const CONTENT_VERSION = "0.3.1";
  try {
    globalThis.__gateLeakContentController?.dispose?.();
  } catch {
    // Older extension contexts may already be invalidated.
  }
  globalThis.__gateLeakContentInstalled = CONTENT_VERSION;

  const denialRules = [
    ["content-violation", /\bcontent[_\s-]?(?:policy[_\s-]?)?violation\b/i],
    ["policy-block", /\b(?:blocked|rejected|denied)\b.{0,40}\b(?:policy|safety|moderation|content)\b/i],
    ["cannot-generate", /\b(?:cannot|can't|unable to|won't)\s+(?:create|generate|help with)\b/i],
    ["not-allowed", /\bnot\s+allowed\b.{0,40}\b(?:policy|content|request|image)\b/i],
    ["zh-policy-violation", /(?:违反|不符合|触犯).{0,24}(?:内容|安全|使用)?(?:政策|规则|准则)/],
    ["zh-third-party-similarity", /(?:第三方内容|内容相似性|与第三方内容相似).{0,32}(?:防护|限制)/],
    ["zh-guardrail-limit", /(?:可能)?违反.{0,48}(?:防护限制|相似性限制)/],
    ["zh-generation-block", /(?:无法|不能|不予|拒绝).{0,16}(?:生成|创建|提供)(?:该|此|这)?(?:图像|图片|内容)?/],
    ["zh-content-block", /(?:内容|请求|图像|图片).{0,16}(?:违规|被阻止|被拒绝)/],
  ];

  let active = false;
  let observer = null;
  let pollingTimer = null;
  let baselineUrls = new Set();
  let customKeywords = ["非常抱歉"];
  let baselineKeywordCounts = [0];
  let keywordOnly = true;
  let denialDetected = false;
  const recentlySent = new Map();

  function send(event) {
    if (!active) return;
    const key = `${event.kind}|${event.url || ""}|${event.action || ""}|${event.rules?.join(",") || ""}`;
    const now = Date.now();
    const previous = recentlySent.get(key) || 0;
    if (now - previous < 250) return;
    recentlySent.set(key, now);

    chrome.runtime.sendMessage({
      type: "DOM_EVENT",
      event: { ...event, epochMs: now },
    }).catch(() => {});
  }

  function urlsFromSrcset(srcset) {
    return String(srcset || "")
      .split(",")
      .map((candidate) => candidate.trim().split(/\s+/, 1)[0])
      .filter(Boolean);
  }

  function urlsFromBackground(element) {
    try {
      const value = getComputedStyle(element).backgroundImage;
      if (!value || value === "none") return [];
      return [...value.matchAll(/url\(["']?(.*?)["']?\)/g)].map((match) => match[1]).filter(Boolean);
    } catch {
      return [];
    }
  }

  function assetUrls(element) {
    const urls = [];
    if (element instanceof HTMLImageElement) {
      if (element.currentSrc) urls.push(element.currentSrc);
      else if (element.src) urls.push(element.src);
      urls.push(...urlsFromSrcset(element.srcset));
    } else if (element instanceof HTMLSourceElement) {
      if (element.src) urls.push(element.src);
      urls.push(...urlsFromSrcset(element.srcset));
    } else if (element instanceof HTMLVideoElement && element.poster) {
      urls.push(element.poster);
    }
    if (element.hasAttribute("style")) urls.push(...urlsFromBackground(element));
    return [...new Set(urls.filter(Boolean))];
  }

  function candidateElements(root) {
    if (!(root instanceof Element)) return [];
    const elements = [];
    if (root.matches("img,source,video,canvas,[style]")) elements.push(root);
    elements.push(...root.querySelectorAll("img,source,video,canvas,[style]"));
    return elements;
  }

  function scanText(text, detectionSource = "mutation", preExisting = false) {
    if (denialDetected) return;
    const value = String(text || "").slice(0, 300000);
    if (!value) return;
    const normalizedValue = value.toLocaleLowerCase();
    const counts = customKeywords.map((keyword) => {
      const needle = String(keyword || "").trim().toLocaleLowerCase();
      if (!needle) return 0;
      let count = 0;
      let offset = 0;
      while (offset < normalizedValue.length) {
        const index = normalizedValue.indexOf(needle, offset);
        if (index < 0) break;
        count += 1;
        offset = index + Math.max(1, needle.length);
      }
      return count;
    });

    if (preExisting) {
      baselineKeywordCounts = counts;
      if (counts.some((count) => count > 0)) {
        send({ kind: "keyword-baseline", counts, detectionSource });
      }
      return;
    }

    const matches = [];
    const isWholePageScan = detectionSource === "poll" || detectionSource === "manual-scan";
    counts.forEach((count, index) => {
      const threshold = isWholePageScan ? (baselineKeywordCounts[index] || 0) : 0;
      if (count > threshold) {
        matches.push(`custom-keyword-${index + 1}`);
      }
    });

    if (!keywordOnly) {
      matches.push(...denialRules.filter(([, pattern]) => pattern.test(value)).map(([code]) => code));
    }

    if (matches.length > 0) {
      denialDetected = true;
      send({
        kind: "denial-text",
        rules: [...new Set(matches)],
        detectionSource,
        preExisting: false,
      });
    }
  }

  function scanCurrentPage(detectionSource = "poll", preExisting = false) {
    if (!active || denialDetected) return;
    const chunks = [document.body?.textContent || document.documentElement?.textContent || ""];
    let shadowCount = 0;
    for (const element of document.querySelectorAll("*")) {
      if (element.shadowRoot && shadowCount < 24) {
        chunks.push(element.shadowRoot.textContent || "");
        shadowCount += 1;
      }
    }
    scanText(chunks.join("\n"), detectionSource, preExisting);
  }

  function scanElement(root, action) {
    for (const element of candidateElements(root)) {
      if (element instanceof HTMLCanvasElement) {
        send({
          kind: "canvas",
          action,
          width: element.width,
          height: element.height,
          tag: "CANVAS",
        });
        continue;
      }

      for (const url of assetUrls(element)) {
        if (action === "added" && baselineUrls.has(url)) continue;
        send({
          kind: action === "removed" ? "asset-removed" : "asset-reference",
          action,
          url,
          tag: element.tagName,
          width: element instanceof HTMLImageElement ? element.naturalWidth : 0,
          height: element instanceof HTMLImageElement ? element.naturalHeight : 0,
        });
      }
    }
  }

  function onLoad(event) {
    const element = event.target;
    if (!(element instanceof HTMLImageElement)) return;
    const url = element.currentSrc || element.src;
    if (!url || baselineUrls.has(url)) return;
    send({
      kind: "image-loaded",
      action: "loaded",
      url,
      tag: "IMG",
      width: element.naturalWidth,
      height: element.naturalHeight,
    });
  }

  function collectBaseline() {
    const urls = new Set();
    for (const element of candidateElements(document.documentElement)) {
      for (const url of assetUrls(element)) urls.add(url);
    }
    return urls;
  }

  function start(settings = {}) {
    stop();
    active = true;
    customKeywords = Array.isArray(settings.denialKeywords) && settings.denialKeywords.length
      ? settings.denialKeywords.slice(0, 12)
      : ["非常抱歉"];
    keywordOnly = settings.keywordOnly !== false;
    denialDetected = false;
    baselineKeywordCounts = customKeywords.map(() => 0);
    recentlySent.clear();
    baselineUrls = collectBaseline();

    observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "childList") {
          for (const node of mutation.addedNodes) {
            if (node instanceof Element) scanElement(node, "added");
            scanText(node.textContent, "mutation", false);
          }
          for (const node of mutation.removedNodes) {
            if (node instanceof Element) scanElement(node, "removed");
          }
        } else if (mutation.type === "attributes" && mutation.target instanceof Element) {
          scanElement(mutation.target, "changed");
        } else if (mutation.type === "characterData") {
          scanText(mutation.target.data || mutation.target.textContent, "character-data", false);
        }
      }
    });

    observer.observe(document.documentElement, {
      subtree: true,
      childList: true,
      attributes: true,
      characterData: true,
      attributeFilter: ["src", "srcset", "poster", "style", "width", "height"],
    });
    document.addEventListener("load", onLoad, true);
    send({
      kind: "observer-ready",
      observerVersion: CONTENT_VERSION,
      frameOrigin: location.origin,
      isTopFrame: window === window.top,
    });
    scanCurrentPage("snapshot", true);
    pollingTimer = setInterval(() => scanCurrentPage("poll", false), 750);
  }

  function stop() {
    active = false;
    observer?.disconnect();
    observer = null;
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = null;
    document.removeEventListener("load", onLoad, true);
  }

  function onRuntimeMessage(message) {
    if (message?.type === "GATELEAK_START") start(message.settings || {});
    if (message?.type === "GATELEAK_SCAN") scanCurrentPage("manual-scan", false);
    if (message?.type === "GATELEAK_STOP") stop();
  }

  chrome.runtime.onMessage.addListener(onRuntimeMessage);
  globalThis.__gateLeakContentController = {
    version: CONTENT_VERSION,
    stop,
    dispose() {
      stop();
      chrome.runtime.onMessage.removeListener(onRuntimeMessage);
    },
  };
})();
