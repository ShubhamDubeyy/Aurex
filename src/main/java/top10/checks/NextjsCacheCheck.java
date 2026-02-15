package top10.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import top10.model.PayloadEntry;
import top10.payloads.PayloadStore;
import top10.util.DiffEngine;
import top10.util.HttpHelper;
import top10.util.IssueHelper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Scanner check module for Next.js cache poisoning and middleware bypass vulnerabilities.
 * <p>
 * Detects Next.js applications via passive fingerprinting, then actively probes for
 * cache poisoning via manipulated headers and URL parameters, as well as the critical
 * middleware subrequest bypass (CVE-2025-29927).
 */
public class NextjsCacheCheck implements CheckModule {

    private static final String MODULE_NAME = "Next.js Cache";
    private static final String MODULE_KEY = "nextjs";

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled = true;

    public NextjsCacheCheck(MontoyaApi api, PayloadStore payloadStore) {
        this.api = api;
        this.payloadStore = payloadStore;
        this.httpHelper = new HttpHelper(api);
    }

    // ------------------------------------------------------------------
    // CheckModule interface
    // ------------------------------------------------------------------

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    // ------------------------------------------------------------------
    // Passive audit
    // ------------------------------------------------------------------

    @Override
    public List<AuditIssue> passiveAudit(HttpRequestResponse baseRequestResponse) {
        try {
            if (!isNextJs(baseRequestResponse)) {
                return Collections.emptyList();
            }

            List<AuditIssue> issues = new ArrayList<>();
            String url = baseRequestResponse.request().url();

            StringBuilder detail = new StringBuilder();
            detail.append("The target application appears to be built with Next.js. ");
            detail.append("Fingerprinting indicators found:<br><ul>");

            if (HttpHelper.bodyContains(baseRequestResponse, "__NEXT_DATA__")) {
                detail.append("<li>Response body contains <code>__NEXT_DATA__</code></li>");
            }
            if (HttpHelper.bodyContains(baseRequestResponse, "_next/static")) {
                detail.append("<li>Response body contains <code>_next/static</code></li>");
            }
            String poweredBy = HttpHelper.getResponseHeader(baseRequestResponse, "x-powered-by");
            if (poweredBy.equalsIgnoreCase("Next.js")) {
                detail.append("<li>Header <code>x-powered-by: Next.js</code></li>");
            }
            String nextjsCache = HttpHelper.getResponseHeader(baseRequestResponse, "x-nextjs-cache");
            if (!nextjsCache.isEmpty()) {
                detail.append("<li>Header <code>x-nextjs-cache: ").append(IssueHelper.escapeHtml(nextjsCache)).append("</code></li>");
            }
            detail.append("</ul>");

            issues.add(IssueHelper.buildIssue(
                    "[Top10-WHT] Next.js Detected",
                    detail.toString(),
                    "Ensure Next.js is up to date and internal headers are not exposed to end users.",
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.CERTAIN,
                    baseRequestResponse));

            return issues;
        } catch (Exception e) {
            api.logging().logToError("NextjsCacheCheck passiveAudit error: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    // ------------------------------------------------------------------
    // Active audit
    // ------------------------------------------------------------------

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        try {
            // Only scan confirmed Next.js applications
            if (!isNextJs(baseRequestResponse)) {
                return Collections.emptyList();
            }

            String url = baseRequestResponse.request().url();

            // ---- Phase 1: Header-based probes ----
            issues.addAll(testHeaders(baseRequestResponse, url));

            // ---- Phase 2: Parameter-based probes ----
            issues.addAll(testParams(baseRequestResponse, url));

        } catch (Exception e) {
            api.logging().logToError("NextjsCacheCheck activeAudit error: " + e.getMessage());
        }

        return issues;
    }

    // ------------------------------------------------------------------
    // Header-based tests
    // ------------------------------------------------------------------

    private List<AuditIssue> testHeaders(HttpRequestResponse baseline, String url) {
        List<AuditIssue> issues = new ArrayList<>();

        List<PayloadEntry> headerPayloads = payloadStore.getEnabled(MODULE_KEY, "nextjs-headers");
        for (PayloadEntry entry : headerPayloads) {
            try {
                String raw = entry.getValue();
                int separatorIdx = raw.indexOf(": ");
                if (separatorIdx < 0) {
                    continue;
                }
                String headerName = raw.substring(0, separatorIdx);
                String headerValue = raw.substring(separatorIdx + 2);

                // Build and send the modified request
                HttpRequest modified = httpHelper.addHeader(baseline.request(), headerName, headerValue);
                HttpRequestResponse probeResponse = httpHelper.sendRequest(modified);

                boolean differs = DiffEngine.responsesDiffer(baseline, probeResponse);

                // --- Special case: x-middleware-subrequest (CVE-2025-29927) ---
                if (headerName.equalsIgnoreCase("x-middleware-subrequest") && differs) {
                    String detail = "The Next.js middleware was bypassed by sending the header "
                            + "<code>" + IssueHelper.escapeHtml(headerName) + ": " + IssueHelper.escapeHtml(headerValue) + "</code>. "
                            + "This indicates the application is vulnerable to CVE-2025-29927, "
                            + "which allows unauthenticated access to middleware-protected routes.<br>"
                            + "Baseline status: " + HttpHelper.statusCode(baseline) + "<br>"
                            + "Probe status: " + HttpHelper.statusCode(probeResponse);

                    issues.add(IssueHelper.buildIssue(
                            "[Top10-WHT] Next.js Middleware Bypass",
                            detail,
                            "Upgrade Next.js to a patched version (>= 15.2.3, >= 14.2.25, >= 13.5.9). "
                                    + "Do not rely solely on middleware for authorization. "
                                    + "Block the <code>x-middleware-subrequest</code> header at the reverse proxy.",
                            url,
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            baseline, probeResponse));
                    continue;
                }

                // --- Special case: x-middleware-prefetch ---
                if (headerName.equalsIgnoreCase("x-middleware-prefetch")) {
                    int baselineLen = HttpHelper.bodyToString(baseline).length();
                    int probeLen = HttpHelper.bodyToString(probeResponse).length();
                    if (probeLen < baselineLen && DiffEngine.lengthDiffers(baseline, probeResponse, 0.15)) {
                        String detail = "Sending <code>" + IssueHelper.escapeHtml(headerName) + ": " + IssueHelper.escapeHtml(headerValue) + "</code> "
                                + "caused the server to return a minimal prefetch response. "
                                + "This can be abused for cache poisoning if the response is cached "
                                + "and served to other users.<br>"
                                + "Baseline body length: " + baselineLen + "<br>"
                                + "Probe body length: " + probeLen;

                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Next.js Cache Poisoning \u2014 Prefetch Header",
                                detail,
                                "Ensure cache keys include the <code>x-middleware-prefetch</code> header "
                                        + "or strip it at the CDN/reverse proxy layer. "
                                        + "Upgrade to Next.js >= 14.2.7 which addresses CVE-2024-46982.",
                                url,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.FIRM,
                                baseline, probeResponse));
                        continue;
                    }
                }

                // --- Special case: Rsc header ---
                if (headerName.equalsIgnoreCase("Rsc")) {
                    String contentType = HttpHelper.getResponseHeader(probeResponse, "content-type");
                    if (contentType.contains("text/x-component")) {
                        String cacheHeader = HttpHelper.getResponseHeader(probeResponse, "x-nextjs-cache");
                        String detail = "Sending <code>Rsc: " + IssueHelper.escapeHtml(headerValue) + "</code> changed the "
                                + "Content-Type to <code>text/x-component</code> (React Server Component stream). "
                                + "If this response is cached under the same cache key as the normal HTML page, "
                                + "users will receive an unusable response.";
                        if (!cacheHeader.isEmpty()) {
                            detail += "<br>Cache header present: <code>x-nextjs-cache: " + IssueHelper.escapeHtml(cacheHeader) + "</code>";
                        }

                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Next.js Cache Poisoning \u2014 RSC Header",
                                detail,
                                "Ensure the <code>Rsc</code> header is included in the cache key, "
                                        + "or add <code>Vary: Rsc</code> in the response.",
                                url,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.FIRM,
                                baseline, probeResponse));
                        continue;
                    }
                }

                // --- Generic header diff ---
                if (differs) {
                    String cacheHeader = HttpHelper.getResponseHeader(probeResponse, "x-nextjs-cache");
                    AuditIssueSeverity severity = cacheHeader.isEmpty()
                            ? AuditIssueSeverity.MEDIUM : AuditIssueSeverity.HIGH;

                    String detail = "Sending the header <code>" + IssueHelper.escapeHtml(headerName) + ": " + IssueHelper.escapeHtml(headerValue)
                            + "</code> caused a different response from the server.<br>"
                            + "Baseline status: " + HttpHelper.statusCode(baseline) + "<br>"
                            + "Probe status: " + HttpHelper.statusCode(probeResponse) + "<br>"
                            + "Body similarity: " + String.format("%.2f", DiffEngine.bodySimilarity(baseline, probeResponse));
                    if (!cacheHeader.isEmpty()) {
                        detail += "<br>Cache header present: <code>x-nextjs-cache: " + IssueHelper.escapeHtml(cacheHeader) + "</code> "
                                + "(indicates cacheability — cache poisoning is likely)";
                    }
                    if (!entry.getDescription().isEmpty()) {
                        detail += "<br>Payload purpose: " + entry.getDescription();
                    }

                    issues.add(IssueHelper.buildIssue(
                            "[Top10-WHT] Next.js Cache Poisoning \u2014 " + headerName,
                            detail,
                            "Include the <code>" + headerName + "</code> header in the cache key, "
                                    + "or strip it at the reverse proxy. "
                                    + "Update Next.js to the latest stable release.",
                            url,
                            severity,
                            AuditIssueConfidence.TENTATIVE,
                            baseline, probeResponse));
                }

            } catch (Exception e) {
                api.logging().logToError("NextjsCacheCheck header test error (" + entry.getValue() + "): " + e.getMessage());
            }
        }

        return issues;
    }

    // ------------------------------------------------------------------
    // Parameter-based tests
    // ------------------------------------------------------------------

    private List<AuditIssue> testParams(HttpRequestResponse baseline, String url) {
        List<AuditIssue> issues = new ArrayList<>();

        List<PayloadEntry> paramPayloads = payloadStore.getEnabled(MODULE_KEY, "nextjs-params");
        for (PayloadEntry entry : paramPayloads) {
            try {
                String raw = entry.getValue();
                int eqIdx = raw.indexOf('=');
                if (eqIdx < 0) {
                    continue;
                }
                String paramName = raw.substring(0, eqIdx);
                String paramValue = raw.substring(eqIdx + 1);

                // Build request with additional URL parameter
                HttpRequest modified = httpHelper.setParameter(
                        baseline.request(), paramName, paramValue,
                        burp.api.montoya.http.message.params.HttpParameterType.URL);
                HttpRequestResponse probeResponse = httpHelper.sendRequest(modified);

                boolean differs = DiffEngine.responsesDiffer(baseline, probeResponse);
                if (!differs) {
                    continue;
                }

                // Check for cache headers — indicates cache poisoning preconditions
                String cacheHeader = HttpHelper.getResponseHeader(probeResponse, "x-nextjs-cache");
                String cacheControl = HttpHelper.getResponseHeader(probeResponse, "cache-control");
                boolean cacheable = !cacheHeader.isEmpty()
                        || (cacheControl.contains("s-maxage") || cacheControl.contains("public"));

                AuditIssueSeverity severity = cacheable
                        ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;

                String detail = "Adding the URL parameter <code>" + IssueHelper.escapeHtml(paramName) + "=" + IssueHelper.escapeHtml(paramValue)
                        + "</code> caused a different response from the server.<br>"
                        + "Baseline status: " + HttpHelper.statusCode(baseline) + "<br>"
                        + "Probe status: " + HttpHelper.statusCode(probeResponse) + "<br>"
                        + "Body similarity: " + String.format("%.2f", DiffEngine.bodySimilarity(baseline, probeResponse));
                if (!cacheHeader.isEmpty()) {
                    detail += "<br>Cache header: <code>x-nextjs-cache: " + IssueHelper.escapeHtml(cacheHeader) + "</code>";
                }
                if (cacheable) {
                    detail += "<br>Response appears cacheable — cache poisoning preconditions exist.";
                }
                if (!entry.getDescription().isEmpty()) {
                    detail += "<br>Payload purpose: " + entry.getDescription();
                }

                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] Next.js Cache Poisoning \u2014 " + paramName + " Parameter",
                        detail,
                        "Ensure the parameter <code>" + paramName + "</code> is included in the cache key "
                                + "or is stripped before reaching the origin. "
                                + "Upgrade to Next.js >= 14.2.7 which addresses cache poisoning via __nextDataReq.",
                        url,
                        severity,
                        AuditIssueConfidence.TENTATIVE,
                        baseline, probeResponse));

            } catch (Exception e) {
                api.logging().logToError("NextjsCacheCheck param test error (" + entry.getValue() + "): " + e.getMessage());
            }
        }

        return issues;
    }

    // ------------------------------------------------------------------
    // Fingerprinting
    // ------------------------------------------------------------------

    /**
     * Returns {@code true} if the response shows indicators of a Next.js application.
     */
    private boolean isNextJs(HttpRequestResponse reqResp) {
        if (reqResp.response() == null) {
            return false;
        }
        if (HttpHelper.bodyContains(reqResp, "__NEXT_DATA__")) {
            return true;
        }
        if (HttpHelper.bodyContains(reqResp, "_next/static")) {
            return true;
        }
        String poweredBy = HttpHelper.getResponseHeader(reqResp, "x-powered-by");
        if (poweredBy.equalsIgnoreCase("Next.js")) {
            return true;
        }
        String nextjsCache = HttpHelper.getResponseHeader(reqResp, "x-nextjs-cache");
        return !nextjsCache.isEmpty();
    }
}
