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
import top10.util.HttpHelper;
import top10.util.IssueHelper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Scanner check module for Unicode normalization vulnerabilities.
 * <p>
 * Detects whether a target normalizes fullwidth Unicode characters to their ASCII
 * equivalents, then determines whether this behaviour can be exploited to bypass
 * WAF rules for XSS, path traversal, and SQL injection.
 * <p>
 * References: CVE-2024-43093, CVE-2025-52488
 */
public class UnicodeCheck implements CheckModule {

    private static final String MODULE_NAME = "Unicode Normalization";
    private static final String MODULE_KEY = "unicode";

    /** Maximum number of fullwidth-map payloads to use during normalization detection. */
    private static final int NORMALIZATION_PROBE_LIMIT = 5;

    /** Mapping from fullwidth Unicode code points to their ASCII equivalents. */
    private static final Map<Character, Character> FULLWIDTH_TO_ASCII = new HashMap<>();

    static {
        // Fullwidth ASCII variants live in U+FF01..U+FF5E and map to U+0021..U+007E
        for (char fw = '\uFF01'; fw <= '\uFF5E'; fw++) {
            char ascii = (char) (fw - 0xFEE0);
            FULLWIDTH_TO_ASCII.put(fw, ascii);
        }
    }

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled = true;

    public UnicodeCheck(MontoyaApi api, PayloadStore payloadStore) {
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
            if (baseRequestResponse.response() == null) {
                return Collections.emptyList();
            }

            List<AuditIssue> issues = new ArrayList<>();
            String url = baseRequestResponse.request().url();

            // Check if response Content-Type is UTF-8 (prerequisite for normalization)
            String contentType = HttpHelper.getResponseHeader(baseRequestResponse, "content-type");
            boolean isUtf8 = contentType.toLowerCase(Locale.ROOT).contains("utf-8");

            if (!isUtf8) {
                return Collections.emptyList();
            }

            // Look for fullwidth characters in the request that may have been normalized
            // in the response (reflected input scenario)
            String requestBody = baseRequestResponse.request().bodyToString();
            String requestPath = baseRequestResponse.request().path();
            String combinedRequest = (requestPath != null ? requestPath : "") + (requestBody != null ? requestBody : "");
            String responseBody = baseRequestResponse.response().bodyToString();

            if (responseBody == null || combinedRequest.isEmpty()) {
                return Collections.emptyList();
            }

            boolean hasFullwidth = false;
            boolean hasNormalized = false;

            for (int i = 0; i < combinedRequest.length(); i++) {
                char c = combinedRequest.charAt(i);
                Character asciiEquiv = FULLWIDTH_TO_ASCII.get(c);
                if (asciiEquiv != null) {
                    hasFullwidth = true;
                    // Check if the ASCII equivalent appears in the response where the
                    // fullwidth version does NOT (suggesting normalization occurred)
                    String asciiStr = String.valueOf(asciiEquiv);
                    if (responseBody.contains(asciiStr) && !responseBody.contains(String.valueOf(c))) {
                        hasNormalized = true;
                        break;
                    }
                }
            }

            if (hasFullwidth && hasNormalized) {
                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] Unicode Normalization \u2014 Normalization Detected",
                        "The endpoint accepts UTF-8 input containing fullwidth Unicode characters "
                                + "and reflects normalized (ASCII) equivalents in the response. "
                                + "This may indicate that server-side Unicode normalization is occurring, "
                                + "which can be leveraged to bypass WAF rules and input filters.<br>"
                                + "Content-Type: <code>" + IssueHelper.escapeHtml(contentType) + "</code>",
                        "Normalize input before applying security filters. "
                                + "Ensure WAF rules operate on the post-normalization form of the input.",
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.TENTATIVE,
                        baseRequestResponse));
            }

            return issues;
        } catch (Exception e) {
            api.logging().logToError("UnicodeCheck passiveAudit error: " + e.getMessage());
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
            String url = baseRequestResponse.request().url();

            // ---- Phase 1: Normalization detection ----
            boolean normalizationDetected = detectNormalization(baseRequestResponse, insertionPoint);
            if (!normalizationDetected) {
                return Collections.emptyList();
            }

            // Report normalization as a medium finding on its own
            issues.add(IssueHelper.buildIssue(
                    "[Top10-WHT] Unicode Normalization \u2014 Normalization Detected",
                    "The target normalizes fullwidth Unicode characters to their ASCII equivalents. "
                            + "Fullwidth characters inserted via the scan insertion point were reflected "
                            + "in their ASCII form in the response body. "
                            + "This is a prerequisite for WAF bypass via Unicode normalization.<br>"
                            + "References: CVE-2024-43093, CVE-2025-52488",
                    "Normalize all input before applying security filters (WAF, input validation). "
                            + "Ensure security checks operate on the canonical form of the input. "
                            + "Consider rejecting requests containing fullwidth Unicode in security-sensitive parameters.",
                    url,
                    AuditIssueSeverity.MEDIUM,
                    AuditIssueConfidence.FIRM,
                    baseRequestResponse));

            // ---- Phase 2: WAF bypass confirmation with attack payloads ----
            issues.addAll(testAttackPayloads(baseRequestResponse, insertionPoint, url));

            // ---- Phase 3: Specific bypass tests ----
            issues.addAll(testSpecificBypasses(baseRequestResponse, insertionPoint, url));

        } catch (Exception e) {
            api.logging().logToError("UnicodeCheck activeAudit error: " + e.getMessage());
        }

        return issues;
    }

    // ------------------------------------------------------------------
    // Phase 1: Normalization detection
    // ------------------------------------------------------------------

    /**
     * Sends a limited number of fullwidth character probes and returns {@code true}
     * if the server normalizes any of them to their ASCII equivalent.
     */
    private boolean detectNormalization(HttpRequestResponse baseline, AuditInsertionPoint insertionPoint) {
        List<PayloadEntry> fullwidthPayloads = payloadStore.getEnabled(MODULE_KEY, "fullwidth-map");
        int limit = Math.min(fullwidthPayloads.size(), NORMALIZATION_PROBE_LIMIT);

        for (int i = 0; i < limit; i++) {
            try {
                PayloadEntry entry = fullwidthPayloads.get(i);
                String fullwidthChar = entry.getValue();

                // Build a test string: "test" + fullwidthChar + "test"
                String testPayload = "test" + fullwidthChar + "test";

                HttpRequest probeRequest = insertionPoint.buildHttpRequestWithPayload(
                        ByteArray.byteArray(testPayload));
                HttpRequestResponse probeResponse = httpHelper.sendRequest(probeRequest);

                if (probeResponse.response() == null) {
                    continue;
                }

                // Determine the ASCII equivalent
                String asciiEquivalent = toAsciiEquivalent(fullwidthChar);
                String expectedNormalized = "test" + asciiEquivalent + "test";

                String responseBody = probeResponse.response().bodyToString();
                if (responseBody != null && responseBody.contains(expectedNormalized)) {
                    return true;
                }
            } catch (Exception e) {
                api.logging().logToError("UnicodeCheck normalization probe error: " + e.getMessage());
            }
        }

        return false;
    }

    // ------------------------------------------------------------------
    // Phase 2: Attack payload testing
    // ------------------------------------------------------------------

    private List<AuditIssue> testAttackPayloads(HttpRequestResponse baseline,
            AuditInsertionPoint insertionPoint, String url) {
        List<AuditIssue> issues = new ArrayList<>();

        List<PayloadEntry> attackPayloads = payloadStore.getEnabled(MODULE_KEY, "attack-payloads");
        for (PayloadEntry entry : attackPayloads) {
            try {
                String unicodePayload = entry.getValue();
                String asciiPayload = toAsciiEquivalent(unicodePayload);

                // Send the ASCII version first to check if it gets blocked
                HttpRequest asciiRequest = insertionPoint.buildHttpRequestWithPayload(
                        ByteArray.byteArray(asciiPayload));
                HttpRequestResponse asciiResponse = httpHelper.sendRequest(asciiRequest);

                boolean asciiBlocked = isBlocked(asciiResponse);

                // Send the fullwidth Unicode version
                HttpRequest unicodeRequest = insertionPoint.buildHttpRequestWithPayload(
                        ByteArray.byteArray(unicodePayload));
                HttpRequestResponse unicodeResponse = httpHelper.sendRequest(unicodeRequest);

                boolean unicodeBlocked = isBlocked(unicodeResponse);

                if (asciiBlocked && !unicodeBlocked) {
                    // WAF bypass confirmed
                    String detail = "A WAF bypass via Unicode normalization was confirmed.<br>"
                            + "The ASCII payload was blocked (status " + HttpHelper.statusCode(asciiResponse)
                            + ") but the fullwidth Unicode equivalent was accepted (status "
                            + HttpHelper.statusCode(unicodeResponse) + ").<br>"
                            + "ASCII payload: <code>" + IssueHelper.escapeHtml(asciiPayload) + "</code><br>"
                            + "Unicode payload: <code>" + IssueHelper.escapeHtml(unicodePayload) + "</code><br>"
                            + "Payload purpose: " + entry.getDescription() + "<br>"
                            + "References: CVE-2024-43093, CVE-2025-52488";

                    issues.add(IssueHelper.buildIssue(
                            "[Top10-WHT] Unicode Normalization \u2014 WAF Bypass Confirmed",
                            detail,
                            "Normalize all input to NFC/NFKC form before applying WAF rules. "
                                    + "Block or reject requests containing fullwidth Unicode in "
                                    + "security-sensitive parameters.",
                            url,
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            asciiResponse, unicodeResponse));
                } else if (!asciiBlocked && !unicodeBlocked) {
                    // Both pass through — normalization still risky but no WAF to bypass
                    String responseBody = unicodeResponse.response() != null
                            ? unicodeResponse.response().bodyToString() : "";
                    if (responseBody != null && responseBody.contains(asciiPayload)) {
                        String detail = "The fullwidth Unicode payload was normalized to its ASCII form "
                                + "and reflected in the response, but no WAF blocking was observed for "
                                + "the ASCII version either.<br>"
                                + "ASCII payload: <code>" + IssueHelper.escapeHtml(asciiPayload) + "</code><br>"
                                + "Unicode payload: <code>" + IssueHelper.escapeHtml(unicodePayload) + "</code><br>"
                                + "Payload purpose: " + entry.getDescription() + "<br>"
                                + "This is still risky because input filters may exist deeper "
                                + "in the application stack.";

                        issues.add(IssueHelper.buildIssue(
                                "[Top10-WHT] Unicode Normalization \u2014 Normalization Detected",
                                detail,
                                "Normalize all input before applying security filters. "
                                        + "Ensure WAF rules operate on the canonical form.",
                                url,
                                AuditIssueSeverity.MEDIUM,
                                AuditIssueConfidence.FIRM,
                                unicodeResponse));
                    }
                }

            } catch (Exception e) {
                api.logging().logToError("UnicodeCheck attack payload error: " + e.getMessage());
            }
        }

        return issues;
    }

    // ------------------------------------------------------------------
    // Phase 3: Specific bypass tests (XSS, path traversal, SQLi)
    // ------------------------------------------------------------------

    private List<AuditIssue> testSpecificBypasses(HttpRequestResponse baseline,
            AuditInsertionPoint insertionPoint, String url) {
        List<AuditIssue> issues = new ArrayList<>();

        // XSS: <script> vs fullwidth equivalent
        issues.addAll(testSpecificBypass(insertionPoint, url,
                "<script>", "\uFF1Cscript\uFF1E",
                "XSS", "XSS via Unicode normalization: the ASCII <code>&lt;script&gt;</code> tag was "
                        + "blocked by the WAF, but the fullwidth equivalent "
                        + "<code>\uFF1Cscript\uFF1E</code> was accepted and may be normalized to "
                        + "<code>&lt;script&gt;</code> on the server side."));

        // Path traversal: ../ vs fullwidth equivalent
        issues.addAll(testSpecificBypass(insertionPoint, url,
                "../", "\uFF0E\uFF0E\uFF0F",
                "Path Traversal", "Path traversal via Unicode normalization: the ASCII "
                        + "<code>../</code> sequence was blocked by the WAF, but the fullwidth equivalent "
                        + "<code>\uFF0E\uFF0E\uFF0F</code> was accepted and may be normalized to "
                        + "<code>../</code> on the server side."));

        // SQL injection: ' vs fullwidth equivalent
        issues.addAll(testSpecificBypass(insertionPoint, url,
                "'", "\uFF07",
                "SQL Injection", "SQL injection via Unicode normalization: the ASCII single quote "
                        + "<code>'</code> was blocked by the WAF, but the fullwidth equivalent "
                        + "<code>\uFF07</code> was accepted and may be normalized to <code>'</code> "
                        + "on the server side."));

        return issues;
    }

    /**
     * Tests a specific ASCII payload vs its fullwidth Unicode equivalent.
     * Returns a finding if ASCII is blocked but Unicode is not.
     */
    private List<AuditIssue> testSpecificBypass(AuditInsertionPoint insertionPoint, String url,
            String asciiPayload, String unicodePayload,
            String bypassType, String detailMessage) {
        List<AuditIssue> issues = new ArrayList<>();

        try {
            // Send ASCII version
            HttpRequest asciiRequest = insertionPoint.buildHttpRequestWithPayload(
                    ByteArray.byteArray(asciiPayload));
            HttpRequestResponse asciiResponse = httpHelper.sendRequest(asciiRequest);

            boolean asciiBlocked = isBlocked(asciiResponse);

            // Send fullwidth Unicode version
            HttpRequest unicodeRequest = insertionPoint.buildHttpRequestWithPayload(
                    ByteArray.byteArray(unicodePayload));
            HttpRequestResponse unicodeResponse = httpHelper.sendRequest(unicodeRequest);

            boolean unicodeBlocked = isBlocked(unicodeResponse);

            if (asciiBlocked && !unicodeBlocked) {
                String detail = detailMessage + "<br>"
                        + "ASCII payload status: " + HttpHelper.statusCode(asciiResponse) + " (blocked)<br>"
                        + "Unicode payload status: " + HttpHelper.statusCode(unicodeResponse) + " (accepted)<br>"
                        + "References: CVE-2024-43093, CVE-2025-52488";

                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] Unicode Normalization \u2014 " + bypassType + " Bypass",
                        detail,
                        "Normalize all input to NFC/NFKC form before applying WAF and input "
                                + "validation rules. Consider blocking fullwidth Unicode characters "
                                + "in security-sensitive contexts.",
                        url,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,
                        asciiResponse, unicodeResponse));
            }
        } catch (Exception e) {
            api.logging().logToError("UnicodeCheck specific bypass test error (" + bypassType + "): " + e.getMessage());
        }

        return issues;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Convert a string of fullwidth Unicode characters to their ASCII equivalents.
     * Characters not in the fullwidth range are left unchanged.
     */
    private String toAsciiEquivalent(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            Character ascii = FULLWIDTH_TO_ASCII.get(c);
            sb.append(ascii != null ? ascii : c);
        }
        return sb.toString();
    }

    /**
     * Returns {@code true} if the response appears to have been blocked by a WAF or
     * security filter (HTTP 403, or body contains common block indicators).
     */
    private boolean isBlocked(HttpRequestResponse reqResp) {
        if (reqResp.response() == null) {
            return false;
        }
        int status = reqResp.response().statusCode();
        if (status == 403) {
            return true;
        }
        return HttpHelper.bodyContains(reqResp, "blocked")
                || HttpHelper.bodyContains(reqResp, "forbidden")
                || HttpHelper.bodyContains(reqResp, "waf")
                || HttpHelper.bodyContains(reqResp, "firewall");
    }
}
