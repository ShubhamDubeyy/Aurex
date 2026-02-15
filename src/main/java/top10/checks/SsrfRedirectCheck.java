package top10.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
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
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Scanner check module for Server-Side Request Forgery (SSRF) via redirect following.
 * Tests whether the application follows redirects to internal targets or cloud metadata endpoints.
 */
public class SsrfRedirectCheck implements CheckModule {

    private static final String MODULE_NAME = "SSRF Redirect";
    private static final String PAYLOAD_MODULE = "ssrf";

    private static final String[] CLOUD_METADATA_INDICATORS = {
            "ami-id", "instance-id", "iam", "security-credentials",
            "computemetadata", "instance/"
    };

    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile(
            "(?:127\\.\\d+\\.\\d+\\.\\d+|10\\.\\d+\\.\\d+\\.\\d+|"
                    + "172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|"
                    + "192\\.168\\.\\d+\\.\\d+|169\\.254\\.\\d+\\.\\d+|"
                    + "localhost|0\\.0\\.0\\.0|\\[::1\\])",
            Pattern.CASE_INSENSITIVE
    );

    private static final String[] INTERNAL_URL_KEYWORDS = {
            "169.254.169.254", "metadata.google.internal", "100.100.100.200",
            "169.254.170.2"
    };

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled;

    public SsrfRedirectCheck(MontoyaApi api, PayloadStore payloadStore) {
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

            // Check Location header for internal IP / cloud metadata redirect
            String location = HttpHelper.getResponseHeader(baseRequestResponse, "Location");
            if (!location.isEmpty()) {
                if (pointsToInternal(location)) {
                    issues.add(IssueHelper.buildIssue(
                            "[Top10-WHT] SSRF \u2014 Server Redirects to Internal Target",
                            "The response contains a <b>Location</b> header that redirects to an internal or "
                                    + "cloud metadata address: <code>" + IssueHelper.escapeHtml(location) + "</code>.<br><br>"
                                    + "This may allow an attacker to reach internal services through the application.",
                            "Validate and restrict redirect targets. Do not redirect to user-controlled URLs "
                                    + "pointing to internal networks or cloud metadata endpoints.",
                            url,
                            AuditIssueSeverity.MEDIUM,
                            AuditIssueConfidence.TENTATIVE,
                            baseRequestResponse));
                }
            }

            // Check response body for leaked cloud metadata content
            String body = HttpHelper.bodyToString(baseRequestResponse);
            if (body != null) {
                String bodyLower = body.toLowerCase(Locale.ROOT);
                for (String indicator : CLOUD_METADATA_INDICATORS) {
                    if (bodyLower.contains(indicator.toLowerCase(Locale.ROOT))) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] SSRF \u2014 Cloud Metadata Content in Response",
                                "The response body contains cloud metadata indicator "
                                        + "<code>" + IssueHelper.escapeHtml(indicator) + "</code>. "
                                        + "This suggests the server may be fetching and returning internal "
                                        + "metadata service content.",
                                "Block access to cloud metadata endpoints from the application. "
                                        + "Use IMDSv2 (AWS) or equivalent protections.",
                                url,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.TENTATIVE,
                                baseRequestResponse));
                        break; // one finding per response for cloud metadata
                    }
                }

                // Check for error messages revealing internal URLs or IPs
                if (INTERNAL_IP_PATTERN.matcher(body).find()
                        && (bodyLower.contains("error") || bodyLower.contains("exception")
                        || bodyLower.contains("failed") || bodyLower.contains("refused"))) {
                    issues.add(IssueHelper.buildIssue(
                            "[Top10-WHT] SSRF \u2014 Internal URL Leaked in Error Message",
                            "The response body contains an error message referencing an internal IP address "
                                    + "or hostname. This may indicate the application attempts server-side requests "
                                    + "that can be influenced by the user.",
                            "Suppress internal network details from error messages returned to clients.",
                            url,
                            AuditIssueSeverity.LOW,
                            AuditIssueConfidence.TENTATIVE,
                            baseRequestResponse));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("SsrfRedirectCheck.passiveAudit error: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String url = baseRequestResponse.request().url();
            String insertionPointName = insertionPoint.name().toLowerCase(Locale.ROOT);

            // ---------- 1. Check if insertion point matches known SSRF-prone parameters ----------
            List<PayloadEntry> urlParams = payloadStore.getEnabled(PAYLOAD_MODULE, "url-params");
            boolean paramMatches = false;
            for (PayloadEntry param : urlParams) {
                if (insertionPointName.equalsIgnoreCase(param.getValue())) {
                    paramMatches = true;
                    break;
                }
            }

            // ---------- 2. For matched URL parameters: test internal targets ----------
            if (paramMatches) {
                List<PayloadEntry> targets = payloadStore.getEnabled(PAYLOAD_MODULE, "internal-targets");
                for (PayloadEntry target : targets) {
                    try {
                        HttpRequest probeRequest = insertionPoint.buildHttpRequestWithPayload(
                                ByteArray.byteArray(target.getValue()));
                        HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                        if (probeResponse.response() == null) {
                            continue;
                        }

                        int status = HttpHelper.statusCode(probeResponse);
                        String targetType = describeTarget(target.getValue());

                        // Check for confirmed SSRF: 200 with cloud metadata content
                        if (status == 200 && containsCloudMetadata(probeResponse)) {
                            issues.add(IssueHelper.buildIssue(
                                    "[Top10-WHT] SSRF \u2014 Server Follows Redirects to " + targetType,
                                    "The server fetched and returned content from the internal target "
                                            + "<code>" + IssueHelper.escapeHtml(target.getValue()) + "</code> "
                                            + "(parameter: <code>" + IssueHelper.escapeHtml(insertionPoint.name()) + "</code>)."
                                            + "<br><br>The response contains cloud metadata indicators confirming SSRF."
                                            + IssueHelper.formatCveRefs(target.getCveRefs()),
                                    "Implement strict URL allow-listing for outbound requests. "
                                            + "Block requests to internal IP ranges and cloud metadata endpoints. "
                                            + "Use IMDSv2 on AWS.",
                                    url,
                                    AuditIssueSeverity.HIGH,
                                    AuditIssueConfidence.FIRM,
                                    baseRequestResponse, probeResponse));
                            continue;
                        }

                        // Check for redirect to internal IP
                        if (status >= 300 && status < 400) {
                            String locationHeader = HttpHelper.getResponseHeader(probeResponse, "Location");
                            if (!locationHeader.isEmpty() && pointsToInternal(locationHeader)) {
                                issues.add(IssueHelper.buildIssue(
                                        "[Top10-WHT] SSRF \u2014 Server Follows Redirects to " + targetType,
                                        "The server returned a redirect (HTTP " + status + ") to an internal address "
                                                + "<code>" + IssueHelper.escapeHtml(locationHeader) + "</code> when the parameter "
                                                + "<code>" + IssueHelper.escapeHtml(insertionPoint.name()) + "</code> was set to "
                                                + "<code>" + IssueHelper.escapeHtml(target.getValue()) + "</code>."
                                                + IssueHelper.formatCveRefs(target.getCveRefs()),
                                        "Validate redirect targets against an allow-list. "
                                                + "Do not follow redirects to internal IP ranges.",
                                        url,
                                        AuditIssueSeverity.MEDIUM,
                                        AuditIssueConfidence.FIRM,
                                        baseRequestResponse, probeResponse));
                                continue;
                            }
                        }

                        // Check for significant response difference
                        if (DiffEngine.responsesDiffer(baseRequestResponse, probeResponse)) {
                            issues.add(IssueHelper.buildIssue(
                                    "[Top10-WHT] SSRF \u2014 Server Follows Redirects to " + targetType,
                                    "The server produced a significantly different response when the parameter "
                                            + "<code>" + IssueHelper.escapeHtml(insertionPoint.name()) + "</code> was set to "
                                            + "<code>" + IssueHelper.escapeHtml(target.getValue()) + "</code>. "
                                            + "The response may indicate the server attempted to fetch the internal URL."
                                            + IssueHelper.formatCveRefs(target.getCveRefs()),
                                    "Restrict outbound requests to an allow-list of external URLs. "
                                            + "Block all internal IP ranges and cloud metadata endpoints.",
                                    url,
                                    AuditIssueSeverity.MEDIUM,
                                    AuditIssueConfidence.TENTATIVE,
                                    baseRequestResponse, probeResponse));
                        }
                    } catch (Exception e) {
                        api.logging().logToError("SsrfRedirectCheck.activeAudit target probe error ("
                                + target.getValue() + "): " + e.getMessage());
                    }
                }
            }

            // ---------- 3. Basic SSRF probes regardless of parameter name ----------
            String[] basicProbes = {"http://127.0.0.1", "http://localhost"};
            for (String probe : basicProbes) {
                try {
                    HttpRequest probeRequest = insertionPoint.buildHttpRequestWithPayload(
                            ByteArray.byteArray(probe));
                    HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                    if (probeResponse.response() == null) {
                        continue;
                    }

                    int status = HttpHelper.statusCode(probeResponse);

                    if (status == 200 && containsCloudMetadata(probeResponse)) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] SSRF \u2014 Server Follows Redirects to Localhost",
                                "The server returned metadata content when the insertion point was set to "
                                        + "<code>" + IssueHelper.escapeHtml(probe) + "</code>. "
                                        + "This confirms a server-side request forgery vulnerability.",
                                "Block server-side requests to localhost and internal networks.",
                                url,
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.FIRM,
                                baseRequestResponse, probeResponse));
                    } else if (DiffEngine.responsesDiffer(baseRequestResponse, probeResponse)) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] SSRF \u2014 Server Follows Redirects to Localhost",
                                "The server produced a different response when the insertion point was set to "
                                        + "<code>" + IssueHelper.escapeHtml(probe) + "</code>. "
                                        + "This may indicate the server is making outbound requests based on user input.",
                                "Validate and restrict outbound request targets. "
                                        + "Block requests to 127.0.0.1 and localhost.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.TENTATIVE,
                                baseRequestResponse, probeResponse));
                    }
                } catch (Exception e) {
                    api.logging().logToError("SsrfRedirectCheck.activeAudit basic probe error ("
                            + probe + "): " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("SsrfRedirectCheck.activeAudit error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    private boolean containsCloudMetadata(HttpRequestResponse reqResp) {
        for (String indicator : CLOUD_METADATA_INDICATORS) {
            if (HttpHelper.bodyContains(reqResp, indicator)) {
                return true;
            }
        }
        return false;
    }

    private boolean pointsToInternal(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        if (INTERNAL_IP_PATTERN.matcher(lower).find()) {
            return true;
        }
        for (String keyword : INTERNAL_URL_KEYWORDS) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private String describeTarget(String target) {
        String lower = target.toLowerCase(Locale.ROOT);
        if (lower.contains("169.254.169.254") || lower.contains("metadata.google.internal")
                || lower.contains("100.100.100.200") || lower.contains("169.254.170.2")) {
            return "Cloud Metadata";
        }
        if (lower.contains("127.0.0.1") || lower.contains("localhost")) {
            return "Localhost";
        }
        return "Internal Network";
    }
}
