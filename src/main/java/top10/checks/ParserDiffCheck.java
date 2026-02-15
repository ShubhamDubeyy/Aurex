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

/**
 * Scanner check module for parser differential attacks.
 * Tests for duplicate JSON keys, method override, content-type confusion, and URL parsing edge cases.
 */
public class ParserDiffCheck implements CheckModule {

    private static final String MODULE_NAME = "Parser Differential";
    private static final String PAYLOAD_MODULE = "parser";

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled;

    public ParserDiffCheck(MontoyaApi api, PayloadStore payloadStore) {
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
            String body = HttpHelper.bodyToString(baseRequestResponse);
            if (body == null) {
                return issues;
            }

            String bodyLower = body.toLowerCase(Locale.ROOT);

            // Check for duplicate key warnings in response
            if (bodyLower.contains("duplicate key")
                    || bodyLower.contains("duplicate field")
                    || bodyLower.contains("duplicate property")) {
                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] Parser Differential \u2014 Duplicate Key Warning Detected",
                        "The response body contains a warning about duplicate JSON keys. "
                                + "This indicates the server-side parser handles duplicate keys and may be "
                                + "susceptible to key-collision attacks where the first vs. last key wins "
                                + "depending on the parser implementation.",
                        "Use a single, well-defined JSON parser that rejects duplicate keys. "
                                + "Validate JSON input strictly before processing.",
                        url,
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.TENTATIVE,
                        baseRequestResponse));
            }

            // Check for JSON parsing error messages
            if (bodyLower.contains("json.parse") || bodyLower.contains("jsondecodeerror")
                    || bodyLower.contains("unexpected token") || bodyLower.contains("json_error")
                    || bodyLower.contains("malformed json") || bodyLower.contains("invalid json")) {
                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] Parser Differential \u2014 JSON Parse Error Exposed",
                        "The response body contains a JSON parsing error message. "
                                + "Exposed parser error details can reveal the server-side parser type and "
                                + "behaviour, aiding parser differential attacks.",
                        "Return generic error messages to clients. Do not expose internal parser "
                                + "error details or stack traces.",
                        url,
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.TENTATIVE,
                        baseRequestResponse));
            }
        } catch (Exception e) {
            api.logging().logToError("ParserDiffCheck.passiveAudit error: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String url = baseRequestResponse.request().url();

            // ------ 1. Duplicate JSON keys ------
            issues.addAll(testDuplicateJsonKeys(baseRequestResponse, url));

            // ------ 2. Method override ------
            issues.addAll(testMethodOverride(baseRequestResponse, url));

            // ------ 3. Content-Type confusion ------
            issues.addAll(testContentTypeConfusion(baseRequestResponse, url));

            // ------ 4. URL parsing edge cases ------
            issues.addAll(testUrlParsing(baseRequestResponse, insertionPoint, url));

        } catch (Exception e) {
            api.logging().logToError("ParserDiffCheck.activeAudit error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Test: Duplicate JSON Keys
    // ---------------------------------------------------------------------------

    private List<AuditIssue> testDuplicateJsonKeys(HttpRequestResponse baseline, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String requestContentType = baseline.request().headerValue("Content-Type");
            if (requestContentType == null || !requestContentType.toLowerCase(Locale.ROOT).contains("json")) {
                return issues;
            }

            List<PayloadEntry> duplicatePayloads = payloadStore.getEnabled(PAYLOAD_MODULE, "duplicate-key");
            for (PayloadEntry payload : duplicatePayloads) {
                try {
                    HttpRequest probeRequest = baseline.request().withBody(payload.getValue());
                    HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                    if (probeResponse.response() == null) {
                        continue;
                    }

                    if (DiffEngine.responsesDiffer(baseline, probeResponse)) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Parser Differential \u2014 Duplicate JSON Key Handling",
                                "Sending a JSON body with duplicate keys caused a different response. "
                                        + "Payload: <code>" + IssueHelper.escapeHtml(payload.getValue()) + "</code><br><br>"
                                        + "Description: " + IssueHelper.escapeHtml(payload.getDescription()) + "<br><br>"
                                        + "The server-side parser may use a first-wins or last-wins strategy for "
                                        + "duplicate keys, which can be exploited to bypass security controls."
                                        + IssueHelper.formatCveRefs(payload.getCveRefs()),
                                "Reject JSON payloads with duplicate keys. Use a strict JSON parser "
                                        + "and validate input schema before processing.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.FIRM,
                                baseline, probeResponse));
                    }
                } catch (Exception e) {
                    api.logging().logToError("ParserDiffCheck duplicate-key probe error: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ParserDiffCheck.testDuplicateJsonKeys error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Test: Method Override
    // ---------------------------------------------------------------------------

    private List<AuditIssue> testMethodOverride(HttpRequestResponse baseline, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            List<PayloadEntry> overridePayloads = payloadStore.getEnabled(PAYLOAD_MODULE, "method-override-headers");
            for (PayloadEntry payload : overridePayloads) {
                try {
                    String payloadValue = payload.getValue();
                    HttpRequest probeRequest;

                    if (payloadValue.contains("=")) {
                        // Body parameter style (e.g., "_method=PUT")
                        String existingBody = baseline.request().bodyToString();
                        String newBody;
                        if (existingBody != null && !existingBody.isEmpty()) {
                            newBody = existingBody + "&" + payloadValue;
                        } else {
                            newBody = payloadValue;
                        }
                        probeRequest = baseline.request().withBody(newBody);
                    } else if (payloadValue.contains(": ")) {
                        // Header style (e.g., "X-HTTP-Method-Override: PUT")
                        String[] parts = payloadValue.split(": ", 2);
                        probeRequest = httpHelper.addHeader(baseline.request(), parts[0], parts[1]);
                    } else {
                        // Unknown format, skip
                        continue;
                    }

                    HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                    if (probeResponse.response() == null) {
                        continue;
                    }

                    if (DiffEngine.responsesDiffer(baseline, probeResponse)) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Parser Differential \u2014 Method Override Accepted",
                                "The server responded differently when a method override was applied "
                                        + "via <code>" + IssueHelper.escapeHtml(payloadValue) + "</code>.<br><br>"
                                        + "Description: " + IssueHelper.escapeHtml(payload.getDescription()) + "<br><br>"
                                        + "This indicates the server accepts HTTP method overrides, which can be "
                                        + "used to bypass access controls or invoke unintended operations."
                                        + IssueHelper.formatCveRefs(payload.getCveRefs()),
                                "Disable HTTP method override headers/parameters in production. "
                                        + "If required, restrict accepted override methods to a safe allow-list.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.FIRM,
                                baseline, probeResponse));
                    }
                } catch (Exception e) {
                    api.logging().logToError("ParserDiffCheck method-override probe error: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ParserDiffCheck.testMethodOverride error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Test: Content-Type Confusion
    // ---------------------------------------------------------------------------

    private List<AuditIssue> testContentTypeConfusion(HttpRequestResponse baseline, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            // Only test if the original request has a body
            String requestBody = baseline.request().bodyToString();
            if (requestBody == null || requestBody.isEmpty()) {
                return issues;
            }

            List<PayloadEntry> contentTypePayloads = payloadStore.getEnabled(PAYLOAD_MODULE, "content-type-confusion");
            for (PayloadEntry payload : contentTypePayloads) {
                try {
                    // Replace the Content-Type header with the confusion payload
                    HttpRequest probeRequest = baseline.request()
                            .withRemovedHeader("Content-Type")
                            .withAddedHeader("Content-Type", payload.getValue());

                    HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                    if (probeResponse.response() == null) {
                        continue;
                    }

                    int status = HttpHelper.statusCode(probeResponse);

                    // If server still processes the body (returns 200), content-type confusion exists
                    if (status == 200) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Parser Differential \u2014 Content-Type Confusion",
                                "The server returned HTTP 200 when the <code>Content-Type</code> header was "
                                        + "changed to <code>" + IssueHelper.escapeHtml(payload.getValue()) + "</code> "
                                        + "while keeping the original request body.<br><br>"
                                        + "Description: " + IssueHelper.escapeHtml(payload.getDescription()) + "<br><br>"
                                        + "This suggests the server does not strictly validate the Content-Type "
                                        + "against the actual body format, which can lead to parser confusion "
                                        + "and security bypasses."
                                        + IssueHelper.formatCveRefs(payload.getCveRefs()),
                                "Strictly validate that the Content-Type header matches the expected "
                                        + "body format. Return 415 Unsupported Media Type for mismatches.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.TENTATIVE,
                                baseline, probeResponse));
                    }
                } catch (Exception e) {
                    api.logging().logToError("ParserDiffCheck content-type probe error: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ParserDiffCheck.testContentTypeConfusion error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Test: URL Parsing Edge Cases
    // ---------------------------------------------------------------------------

    private List<AuditIssue> testUrlParsing(HttpRequestResponse baseline, AuditInsertionPoint insertionPoint, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            List<PayloadEntry> urlPayloads = payloadStore.getEnabled(PAYLOAD_MODULE, "url-parsing");
            for (PayloadEntry payload : urlPayloads) {
                try {
                    HttpRequest probeRequest = insertionPoint.buildHttpRequestWithPayload(
                            ByteArray.byteArray(payload.getValue()));
                    HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                    if (probeResponse.response() == null) {
                        continue;
                    }

                    // Check for path traversal indicators or unexpected content
                    boolean hasAdminContent = HttpHelper.bodyContains(probeResponse, "admin")
                            || HttpHelper.bodyContains(probeResponse, "dashboard")
                            || HttpHelper.bodyContains(probeResponse, "configuration");

                    boolean responseDiffers = DiffEngine.responsesDiffer(baseline, probeResponse);

                    if (responseDiffers && hasAdminContent) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Parser Differential \u2014 URL Parsing Bypass",
                                "A URL parsing edge case payload caused the server to return unexpected "
                                        + "content that may include administrative or restricted data.<br><br>"
                                        + "Payload: <code>" + IssueHelper.escapeHtml(payload.getValue()) + "</code><br>"
                                        + "Description: " + IssueHelper.escapeHtml(payload.getDescription())
                                        + IssueHelper.formatCveRefs(payload.getCveRefs()),
                                "Normalize and canonicalize URL paths before routing. "
                                        + "Reject requests containing path traversal sequences.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.FIRM,
                                baseline, probeResponse));
                    } else if (responseDiffers) {
                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Parser Differential \u2014 URL Parsing Anomaly",
                                "A URL parsing edge case payload produced a different response, "
                                        + "indicating the server's URL parser may handle edge cases in an "
                                        + "exploitable way.<br><br>"
                                        + "Payload: <code>" + IssueHelper.escapeHtml(payload.getValue()) + "</code><br>"
                                        + "Description: " + IssueHelper.escapeHtml(payload.getDescription())
                                        + IssueHelper.formatCveRefs(payload.getCveRefs()),
                                "Use a single, consistent URL parser. Normalize paths before routing. "
                                        + "Reject URLs with ambiguous syntax.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.TENTATIVE,
                                baseline, probeResponse));
                    }
                } catch (Exception e) {
                    api.logging().logToError("ParserDiffCheck url-parsing probe error: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("ParserDiffCheck.testUrlParsing error: " + e.getMessage());
        }
        return issues;
    }
}
