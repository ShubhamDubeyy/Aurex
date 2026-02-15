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
import top10.util.HttpHelper;
import top10.util.IssueHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Scanner check module for HTTP/2 CONNECT tunnel abuse.
 * Detects HTTP/2 support and attempts to open CONNECT tunnels to internal targets.
 * Best-effort due to Montoya API limitations with the CONNECT method.
 *
 * <p>Related CVEs: CVE-2025-49630, CVE-2025-53020</p>
 */
public class Http2ConnectCheck implements CheckModule {

    private static final String MODULE_NAME = "HTTP/2 CONNECT";
    private static final String PAYLOAD_MODULE = "http2";

    private static final String CVE_TUNNEL = "CVE-2025-49630";
    private static final String CVE_SMUGGLING = "CVE-2025-53020";

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled;

    public Http2ConnectCheck(MontoyaApi api, PayloadStore payloadStore) {
        this.api = api;
        this.payloadStore = payloadStore;
        this.httpHelper = new HttpHelper(api);
        this.enabled = true;
    }

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

    @Override
    public List<AuditIssue> passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            if (baseRequestResponse.response() == null) {
                return issues;
            }

            String url = baseRequestResponse.request().url();

            // Check for HTTP/2 indicators in response headers
            boolean http2Detected = false;
            String detectionDetail = "";

            // alt-svc header containing h2 or h3
            String altSvc = HttpHelper.getResponseHeader(baseRequestResponse, "alt-svc");
            if (!altSvc.isEmpty()) {
                String altSvcLower = altSvc.toLowerCase(Locale.ROOT);
                if (altSvcLower.contains("h2") || altSvcLower.contains("h3")) {
                    http2Detected = true;
                    detectionDetail = "The <code>alt-svc</code> header advertises HTTP/2 or HTTP/3 support: "
                            + "<code>" + IssueHelper.escapeHtml(altSvc) + "</code>";
                }
            }

            // upgrade header containing h2c
            String upgrade = HttpHelper.getResponseHeader(baseRequestResponse, "upgrade");
            if (!upgrade.isEmpty()) {
                String upgradeLower = upgrade.toLowerCase(Locale.ROOT);
                if (upgradeLower.contains("h2c") || upgradeLower.contains("h2")) {
                    http2Detected = true;
                    if (detectionDetail.isEmpty()) {
                        detectionDetail = "The <code>upgrade</code> header indicates HTTP/2 cleartext (h2c) support: "
                                + "<code>" + IssueHelper.escapeHtml(upgrade) + "</code>";
                    } else {
                        detectionDetail += "<br>Additionally, the <code>upgrade</code> header indicates h2c support: "
                                + "<code>" + IssueHelper.escapeHtml(upgrade) + "</code>";
                    }
                }
            }

            if (http2Detected) {
                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] HTTP/2 Detected",
                        "HTTP/2 support was detected on this host.<br><br>"
                                + detectionDetail + "<br><br>"
                                + "HTTP/2 CONNECT tunnelling may allow an attacker to establish TCP tunnels "
                                + "through the server to reach internal services. Manual testing with an HTTP/2 "
                                + "client (e.g., <code>curl --http2</code> or <code>h2csmuggler</code>) is "
                                + "recommended.<br><br>"
                                + "<b>Related CVEs:</b> " + CVE_TUNNEL + ", " + CVE_SMUGGLING,
                        "Disable HTTP/2 CONNECT on forward-facing servers unless explicitly required. "
                                + "If HTTP/2 is needed, ensure CONNECT requests are denied or restricted "
                                + "to authorised targets only.",
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.CERTAIN,
                        baseRequestResponse));
            }

            // Check for CVE indicators: Apache with HTTP/2 modules
            String server = HttpHelper.getResponseHeader(baseRequestResponse, "Server");
            if (!server.isEmpty()) {
                String serverLower = server.toLowerCase(Locale.ROOT);
                if (serverLower.contains("apache") && http2Detected) {
                    issues.add(IssueHelper.buildIssue(
                            "[Top10-WHT] HTTP/2 Detected \u2014 Apache HTTP/2 Module",
                            "An Apache server with HTTP/2 support was detected: "
                                    + "<code>" + IssueHelper.escapeHtml(server) + "</code>.<br><br>"
                                    + "Apache's mod_http2 has historically been vulnerable to CONNECT tunnel "
                                    + "abuse and request smuggling. Verify the Apache version is patched against "
                                    + "known HTTP/2 vulnerabilities.<br><br>"
                                    + "<b>Related CVEs:</b> " + CVE_TUNNEL + ", " + CVE_SMUGGLING,
                            "Update Apache to the latest patched version. Disable mod_proxy_http2 CONNECT "
                                    + "if not required. Review Apache HTTP/2 security advisories.",
                            url,
                            AuditIssueSeverity.LOW,
                            AuditIssueConfidence.TENTATIVE,
                            baseRequestResponse));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Http2ConnectCheck.passiveAudit error: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            if (baseRequestResponse.response() == null) {
                return issues;
            }

            String url = baseRequestResponse.request().url();

            // Detect HTTP/2 from baseline response headers
            if (!isHttp2Detected(baseRequestResponse)) {
                api.logging().logToOutput("Http2ConnectCheck: No HTTP/2 indicators found, skipping active scan for "
                        + url);
                return issues;
            }

            api.logging().logToOutput("Http2ConnectCheck: HTTP/2 detected, testing CONNECT tunnels for " + url);

            // Get connect-targets payloads
            List<PayloadEntry> connectTargets = payloadStore.getEnabled(PAYLOAD_MODULE, "connect-targets");
            for (PayloadEntry target : connectTargets) {
                try {
                    // Build a CONNECT-style request
                    // Note: The Montoya API may not fully support the CONNECT method.
                    // This is a best-effort attempt.
                    String targetValue = target.getValue();
                    String connectRaw = "CONNECT " + targetValue + " HTTP/2\r\n"
                            + "Host: " + targetValue + "\r\n"
                            + "\r\n";

                    HttpRequest connectRequest = HttpRequest.httpRequest(
                            baseRequestResponse.request().httpService(),
                            connectRaw);

                    HttpRequestResponse connectResponse = httpHelper.sendRequest(connectRequest);

                    if (connectResponse.response() == null) {
                        continue;
                    }

                    int status = HttpHelper.statusCode(connectResponse);

                    if (status == 200) {
                        // Tunnel established
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] HTTP/2 CONNECT Tunnel Open \u2014 " + IssueHelper.escapeHtml(targetValue),
                                "An HTTP/2 CONNECT tunnel was successfully established to "
                                        + "<code>" + IssueHelper.escapeHtml(targetValue) + "</code> "
                                        + "(HTTP 200 returned).<br><br>"
                                        + "This allows an attacker to relay TCP traffic through the server to "
                                        + "the internal target, potentially accessing databases, caches, admin "
                                        + "panels, or cloud metadata services."
                                        + IssueHelper.formatCveRefs(target.getCveRefs())
                                        + "<br><b>Additional CVEs:</b> " + CVE_TUNNEL + ", " + CVE_SMUGGLING,
                                "Disable HTTP/2 CONNECT on public-facing servers. If CONNECT is required, "
                                        + "restrict allowed target hosts and ports to a strict allow-list.",
                                url,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.FIRM,
                                baseRequestResponse, connectResponse));
                    } else if (status == 407) {
                        // Proxy authentication required -- the tunnel exists but needs auth
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] HTTP/2 CONNECT Tunnel Open \u2014 " + IssueHelper.escapeHtml(targetValue),
                                "The server returned HTTP 407 (Proxy Authentication Required) for a CONNECT "
                                        + "request to <code>" + IssueHelper.escapeHtml(targetValue) + "</code>.<br><br>"
                                        + "This confirms the server acts as an HTTP/2 proxy and accepts CONNECT "
                                        + "requests. With valid credentials, an attacker could tunnel traffic to "
                                        + "internal targets."
                                        + IssueHelper.formatCveRefs(target.getCveRefs())
                                        + "<br><b>Additional CVEs:</b> " + CVE_TUNNEL + ", " + CVE_SMUGGLING,
                                "Disable HTTP/2 CONNECT if proxy functionality is not intended. "
                                        + "If required, enforce strong authentication and restrict target hosts.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.FIRM,
                                baseRequestResponse, connectResponse));
                    }
                    // Other status codes (403, 405, etc.) are expected denials -- not reported
                } catch (Exception e) {
                    // The Montoya API may not support CONNECT method -- this is expected
                    api.logging().logToOutput("Http2ConnectCheck: HTTP/2 CONNECT not fully supported "
                            + "by Montoya API for target " + target.getValue() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Http2ConnectCheck.activeAudit error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    /**
     * Checks response headers for HTTP/2 indicators.
     */
    private boolean isHttp2Detected(HttpRequestResponse reqResp) {
        try {
            String altSvc = HttpHelper.getResponseHeader(reqResp, "alt-svc");
            if (!altSvc.isEmpty()) {
                String lower = altSvc.toLowerCase(Locale.ROOT);
                if (lower.contains("h2") || lower.contains("h3")) {
                    return true;
                }
            }

            String upgrade = HttpHelper.getResponseHeader(reqResp, "upgrade");
            if (!upgrade.isEmpty()) {
                String lower = upgrade.toLowerCase(Locale.ROOT);
                if (lower.contains("h2c") || lower.contains("h2")) {
                    return true;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Http2ConnectCheck.isHttp2Detected error: " + e.getMessage());
        }
        return false;
    }
}
