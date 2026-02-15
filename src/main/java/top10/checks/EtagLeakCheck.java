package top10.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import top10.util.HttpHelper;
import top10.util.IssueHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Scanner check module for ETag-based cross-site leak (XS-Leak) preconditions.
 * Examines whether ETag headers, combined with missing cache controls and Vary headers,
 * create the preconditions for an XS-Leak attack where an attacker can infer a victim's
 * authentication state or identity by observing ETag differences.
 */
public class EtagLeakCheck implements CheckModule {

    private static final String MODULE_NAME = "ETag XS-Leak";
    private static final String PAYLOAD_MODULE = "etag";

    private final MontoyaApi api;
    private final HttpHelper httpHelper;
    private volatile boolean enabled;

    public EtagLeakCheck(MontoyaApi api) {
        this.api = api;
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

            // Check if response has ETag header
            String etag = HttpHelper.getResponseHeader(baseRequestResponse, "ETag");
            if (etag.isEmpty()) {
                return issues;
            }

            api.logging().logToOutput("EtagLeakCheck: ETag found on " + url + ": " + etag);

            // Evaluate preconditions
            boolean noStorePresent = false;
            boolean varyCoversAuth = false;
            boolean isWeakEtag = etag.startsWith("W/\"") || etag.startsWith("w/\"");

            // Check Cache-Control for no-store
            String cacheControl = HttpHelper.getResponseHeader(baseRequestResponse, "Cache-Control");
            if (!cacheControl.isEmpty()) {
                String ccLower = cacheControl.toLowerCase(Locale.ROOT);
                if (ccLower.contains("no-store")) {
                    noStorePresent = true;
                }
            }

            // Check Vary header for Cookie or Authorization
            String vary = HttpHelper.getResponseHeader(baseRequestResponse, "Vary");
            if (!vary.isEmpty()) {
                String varyLower = vary.toLowerCase(Locale.ROOT);
                if (varyLower.contains("cookie") || varyLower.contains("authorization")) {
                    varyCoversAuth = true;
                }
            }

            // Count how many preconditions are met for XS-Leak
            int preconditionsMet = 0;
            List<String> findings = new ArrayList<>();

            if (!noStorePresent) {
                preconditionsMet++;
                findings.add("Missing <code>Cache-Control: no-store</code> directive");
            }

            if (!varyCoversAuth) {
                preconditionsMet++;
                findings.add("Missing <code>Vary: Cookie</code> or <code>Vary: Authorization</code> header");
            }

            if (isWeakEtag) {
                preconditionsMet++;
                findings.add("Weak ETag (<code>" + IssueHelper.escapeHtml(etag) + "</code>) is more exploitable "
                        + "because it survives content-encoding changes");
            }

            // Report if ETag present AND no-store missing AND Vary does not cover auth
            if (!noStorePresent && !varyCoversAuth) {
                StringBuilder detail = new StringBuilder();
                detail.append("The response includes an ETag header (<code>")
                        .append(IssueHelper.escapeHtml(etag))
                        .append("</code>) with missing cache protections that could enable ETag-based "
                                + "cross-site leak attacks.<br><br>");
                detail.append("<b>Preconditions identified (")
                        .append(preconditionsMet)
                        .append("/3):</b><ul>");
                for (String finding : findings) {
                    detail.append("<li>").append(finding).append("</li>");
                }
                detail.append("</ul>");
                detail.append("An attacker could potentially use the ETag to detect whether a victim "
                        + "is authenticated or to fingerprint the victim's session by comparing ETag "
                        + "values across different authentication states.");

                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] ETag XS-Leak Preconditions Present",
                        detail.toString(),
                        "Add <code>Cache-Control: no-store</code> to responses containing "
                                + "user-specific content. Include <code>Cookie</code> and/or "
                                + "<code>Authorization</code> in the <code>Vary</code> header so caches "
                                + "differentiate responses by authentication state. Consider removing ETag "
                                + "headers from authenticated endpoints.",
                        url,
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.TENTATIVE,
                        baseRequestResponse));
            }
        } catch (Exception e) {
            api.logging().logToError("EtagLeakCheck.passiveAudit error: " + e.getMessage());
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

            // Check if response has ETag header
            String authenticatedEtag = HttpHelper.getResponseHeader(baseRequestResponse, "ETag");
            if (authenticatedEtag.isEmpty()) {
                return issues;
            }

            api.logging().logToOutput("EtagLeakCheck: Active scan - testing ETag diff for " + url);

            // Send the same request WITHOUT cookies (unauthenticated)
            HttpRequest unauthRequest = baseRequestResponse.request().withRemovedHeader("Cookie");
            // Also remove Authorization header for completeness
            unauthRequest = unauthRequest.withRemovedHeader("Authorization");

            HttpRequestResponse unauthResponse;
            try {
                unauthResponse = httpHelper.sendRequest(unauthRequest);
            } catch (Exception e) {
                api.logging().logToError("EtagLeakCheck: Failed to send unauthenticated request: "
                        + e.getMessage());
                return issues;
            }

            if (unauthResponse.response() == null) {
                return issues;
            }

            String unauthEtag = HttpHelper.getResponseHeader(unauthResponse, "ETag");
            if (unauthEtag.isEmpty()) {
                // No ETag in unauthenticated response -- cannot compare
                api.logging().logToOutput("EtagLeakCheck: No ETag in unauthenticated response for " + url);
                return issues;
            }

            // Compare ETag values
            boolean etagsDiffer = !authenticatedEtag.equals(unauthEtag);

            // Compare body lengths
            int authBodyLen = bodyLength(baseRequestResponse);
            int unauthBodyLen = bodyLength(unauthResponse);
            boolean bodyLengthsDiffer = authBodyLen != unauthBodyLen;

            if (etagsDiffer && bodyLengthsDiffer) {
                // XS-Leak preconditions confirmed
                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] ETag XS-Leak Preconditions Present",
                        "Active verification confirmed that the ETag differs between authenticated and "
                                + "unauthenticated requests, and the response body lengths also differ.<br><br>"
                                + "<b>Authenticated ETag:</b> <code>" + IssueHelper.escapeHtml(authenticatedEtag) + "</code> "
                                + "(body length: " + authBodyLen + ")<br>"
                                + "<b>Unauthenticated ETag:</b> <code>" + IssueHelper.escapeHtml(unauthEtag) + "</code> "
                                + "(body length: " + unauthBodyLen + ")<br><br>"
                                + "An attacker can exploit this difference to detect a victim's authentication "
                                + "state using cross-site ETag probing. By caching an unauthenticated response "
                                + "and then re-requesting with <code>If-None-Match</code>, a 200 vs 304 "
                                + "difference reveals the victim's login status.",
                        "Add <code>Cache-Control: no-store</code> to authenticated endpoints. "
                                + "Include <code>Vary: Cookie, Authorization</code> in the response. "
                                + "Consider removing ETag headers from endpoints that serve different "
                                + "content based on authentication.",
                        url,
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.FIRM,
                        baseRequestResponse, unauthResponse));
            } else if (etagsDiffer) {
                // ETags differ but body lengths are the same -- less exploitable but notable
                issues.add(IssueHelper.buildIssue(
                        "[Top10-WHT] ETag XS-Leak Preconditions Present",
                        "The ETag differs between authenticated and unauthenticated requests, "
                                + "although the response body lengths are identical.<br><br>"
                                + "<b>Authenticated ETag:</b> <code>" + IssueHelper.escapeHtml(authenticatedEtag) + "</code><br>"
                                + "<b>Unauthenticated ETag:</b> <code>" + IssueHelper.escapeHtml(unauthEtag) + "</code><br><br>"
                                + "While the identical body lengths reduce exploitability, the differing ETags "
                                + "could still allow authentication state detection via conditional requests.",
                        "Add <code>Cache-Control: no-store</code> to authenticated endpoints. "
                                + "Include <code>Vary: Cookie, Authorization</code> in the response.",
                        url,
                        AuditIssueSeverity.LOW,
                        AuditIssueConfidence.TENTATIVE,
                        baseRequestResponse, unauthResponse));
            }
            // If ETags are the same for different auth states, no XS-Leak is possible -- skip
        } catch (Exception e) {
            api.logging().logToError("EtagLeakCheck.activeAudit error: " + e.getMessage());
        }
        return issues;
    }

    // ---------------------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------------------

    private static int bodyLength(HttpRequestResponse reqResp) {
        try {
            if (reqResp.response() == null) {
                return 0;
            }
            String body = reqResp.response().bodyToString();
            return body != null ? body.length() : 0;
        } catch (Exception e) {
            return 0;
        }
    }
}
