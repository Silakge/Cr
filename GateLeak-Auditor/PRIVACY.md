# Privacy and Security Notes

GateLeak Auditor is designed for local, authorized research.

## Data handled transiently

While an audit is active, the extension may transiently receive:

- response bodies from candidate image and API requests;
- full request or asset URLs;
- WebSocket or Server-Sent Event payloads;
- DOM asset URLs and limited text added to the page.

This transient access is necessary to determine whether image data or a denial signal reached the browser. The extension immediately reduces these inputs to metadata.

## Data retained for the browser session

The extension retains only:

- target origin;
- event timestamps and evidence categories;
- HTTP status, MIME type, response size and cache source;
- redacted URL display values and short local fingerprints;
- truncated SHA-256 values for response-body correlation;
- matched rule names and field names, not the matched text or identifier values.
- user-configured denial keywords, so the audit can be reproduced; avoid entering secrets as keywords.

By default it does not retain response bodies, prompts, cookies, authorization headers, raw signed URLs, images or identifier values.

If the user explicitly enables **Retain candidate images (research mode)** before an audit, the extension may separately retain up to three verified raster-image candidates already received by the browser. Each image is limited to 3 MB and the combined decoded size is limited to 5 MB. These captures stay in `chrome.storage.session`, are never embedded in the redacted JSON export, and are removed when the user clears the audit or when session storage is reset. Stopping an audit does not remove them so the user can export a candidate for authorized local review.

State is stored in `chrome.storage.session`. It is cleared when Chrome restarts or the extension is reloaded, disabled or updated. The user may clear it at any time from the popup.

## Network behavior

The extension does not make outbound requests. It does not replay observed URLs, fetch blocked assets, bypass service workers, disable caches, modify request headers or block deletion/moderation calls.

## Export

Export is user initiated. The JSON file contains only the reduced audit state and never includes retained image bodies, but can still reveal the target origin, timing, byte sizes and field names. Image export is a separate per-event action available only for candidates retained through the opt-in research mode. Review every artifact before sharing.

## Permission rationale

- `debugger`: subscribes to Chrome DevTools Protocol network events and reads already received response bodies for local classification.
- `activeTab`: limits scripting access to the tab on which the user invokes the extension.
- `scripting`: injects the passive DOM observer after the user starts an audit.
- `storage`: stores the current audit in memory-backed session storage.

Opening Chrome DevTools on an attached tab terminates the debugger session. The extension reports this as an interrupted audit.
