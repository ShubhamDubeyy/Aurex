package top10.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class SstiCheck implements CheckModule {

    private static final String MODULE_NAME = "SSTI";
    private static final String PAYLOAD_MODULE = "ssti";
    private static final String ISSUE_PREFIX = "[Top10-WHT] SSTI Detected \u2014 ";

    private static final List<String> ERROR_SIGNATURES = Arrays.asList(
            "TemplateSyntaxError", "UndefinedError", "Twig_Error", "twig error",
            "freemarker.core.InvalidReferenceException", "freemarker.core.ParseException",
            "org.apache.velocity", "ParseErrorException",
            "com.mitchellbosecke.pebble", "Jinja2", "jinja2.exceptions",
            "Mako", "mako.exceptions", "Slim::Temple",
            "EvalError", "Handlebars.Exception", "handlebars"
    );

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled;

    public SstiCheck(MontoyaApi api, PayloadStore payloadStore) {
        this.api = api;
        this.payloadStore = payloadStore;
        this.httpHelper = new HttpHelper(api);
        this.enabled = true;
    }

    @Override public String getName() { return MODULE_NAME; }
    @Override public boolean isEnabled() { return enabled; }
    @Override public void setEnabled(boolean enabled) { this.enabled = enabled; }

    @Override
    public List<AuditIssue> passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            if (baseRequestResponse.response() == null) return issues;
            String body = HttpHelper.bodyToString(baseRequestResponse);
            if (body.isEmpty()) return issues;
            String bodyLower = body.toLowerCase(Locale.ROOT);
            String url = baseRequestResponse.request().url();

            for (String signature : ERROR_SIGNATURES) {
                if (bodyLower.contains(signature.toLowerCase(Locale.ROOT))) {
                    issues.add(IssueHelper.buildIssue(
                            ISSUE_PREFIX + "Error Signature in Response",
                            "The response body contains a template engine error signature: <b>"
                                    + IssueHelper.escapeHtml(signature) + "</b>.<br><br>"
                                    + "This may indicate a server-side template engine is in use and "
                                    + "leaking error information.",
                            "Ensure user input is never passed directly into template expressions. "
                                    + "Disable debug/verbose error output in production.",
                            url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
                            baseRequestResponse));
                    break;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("SstiCheck passiveAudit error: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String url = baseRequestResponse.request().url();
            int baselineStatus = HttpHelper.statusCode(baseRequestResponse);
            String baselineBody = HttpHelper.bodyToString(baseRequestResponse);

            // Phase 1: Polyglot payloads — check for math eval
            AuditIssue polyglotIssue = testPolyglotPayloads(baseRequestResponse, insertionPoint, url, baselineBody);
            if (polyglotIssue != null) { issues.add(polyglotIssue); return issues; }

            // Phase 2: Error-trigger payloads — detect status code changes
            AuditIssue errorIssue = testErrorTriggerPayloads(baseRequestResponse, insertionPoint, url, baselineStatus);
            if (errorIssue != null) issues.add(errorIssue);

            // Phase 3: Engine-detect payloads
            AuditIssue engineIssue = testEngineDetectPayloads(baseRequestResponse, insertionPoint, url);
            if (engineIssue != null) { issues.add(engineIssue); return issues; }

            // Phase 4: Error-based blind payloads
            AuditIssue blindIssue = testErrorBasedBlindPayloads(baseRequestResponse, insertionPoint, url);
            if (blindIssue != null) issues.add(blindIssue);

        } catch (Exception e) {
            api.logging().logToError("SstiCheck activeAudit error: " + e.getMessage());
        }
        return issues;
    }

    private AuditIssue testPolyglotPayloads(HttpRequestResponse base, AuditInsertionPoint ip,
                                              String url, String baselineBody) {
        List<PayloadEntry> polyglots = payloadStore.getEnabled(PAYLOAD_MODULE, "polyglot");
        for (PayloadEntry entry : polyglots) {
            try {
                HttpRequestResponse probe = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(entry.getValue())));
                if (probe.response() == null) continue;

                String probeBody = HttpHelper.bodyToString(probe);
                // Check for "49" only if it wasn't already in the baseline response
                // This prevents false positives from pages that naturally contain "49"
                if (probeBody.contains("49") && !baselineBody.contains("49")) {
                    String engine = attemptEngineIdentification(probe);
                    return IssueHelper.buildIssue(
                            ISSUE_PREFIX + engine,
                            "The polyglot payload <b>" + IssueHelper.escapeHtml(entry.getValue())
                                    + "</b> caused the server to evaluate a math expression (7*7=49), "
                                    + "confirming SSTI.<br><br>"
                                    + "Detected engine: <b>" + IssueHelper.escapeHtml(engine) + "</b>"
                                    + IssueHelper.formatCveRefs(entry.getCveRefs()),
                            "Never pass user-controlled input directly into template expressions.",
                            url, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN, base, probe);
                }
            } catch (Exception e) {
                api.logging().logToError("SstiCheck polyglot error: " + e.getMessage());
            }
        }
        return null;
    }

    private AuditIssue testErrorTriggerPayloads(HttpRequestResponse base, AuditInsertionPoint ip,
                                                  String url, int baselineStatus) {
        List<PayloadEntry> triggers = payloadStore.getEnabled(PAYLOAD_MODULE, "error-trigger");
        for (PayloadEntry entry : triggers) {
            try {
                HttpRequestResponse probe = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(entry.getValue())));
                if (probe.response() == null) continue;

                int probeStatus = HttpHelper.statusCode(probe);
                if (probeStatus != baselineStatus) {
                    return IssueHelper.buildIssue(
                            ISSUE_PREFIX + "Potential (Error Trigger)",
                            "The error-trigger payload <b>" + IssueHelper.escapeHtml(entry.getValue())
                                    + "</b> caused a status code change from " + baselineStatus
                                    + " to " + probeStatus + ", suggesting template syntax is being parsed."
                                    + IssueHelper.formatCveRefs(entry.getCveRefs()),
                            "Sanitise input before passing to template engines. Disable verbose error responses.",
                            url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE, base, probe);
                }
            } catch (Exception e) {
                api.logging().logToError("SstiCheck error-trigger error: " + e.getMessage());
            }
        }
        return null;
    }

    private AuditIssue testEngineDetectPayloads(HttpRequestResponse base, AuditInsertionPoint ip, String url) {
        List<PayloadEntry> detectors = payloadStore.getEnabled(PAYLOAD_MODULE, "engine-detect");
        for (PayloadEntry entry : detectors) {
            try {
                HttpRequestResponse probe = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(entry.getValue())));
                if (probe.response() == null) continue;

                String expected = entry.getExpectedResponse();
                if (expected == null || expected.isEmpty()) continue;

                String engine = matchExpectedResponse(probe, expected);
                if (engine != null) {
                    return IssueHelper.buildIssue(
                            ISSUE_PREFIX + engine,
                            "The engine-detect payload <b>" + IssueHelper.escapeHtml(entry.getValue())
                                    + "</b> confirmed <b>" + IssueHelper.escapeHtml(engine)
                                    + "</b> template engine."
                                    + IssueHelper.formatCveRefs(entry.getCveRefs()),
                            "Remove or sandbox the identified template engine (" + IssueHelper.escapeHtml(engine) + ").",
                            url, AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN, base, probe);
                }
            } catch (Exception e) {
                api.logging().logToError("SstiCheck engine-detect error: " + e.getMessage());
            }
        }
        return null;
    }

    private AuditIssue testErrorBasedBlindPayloads(HttpRequestResponse base, AuditInsertionPoint ip, String url) {
        List<PayloadEntry> blindPayloads = payloadStore.getEnabled(PAYLOAD_MODULE, "error-based-blind");
        for (int i = 0; i + 1 < blindPayloads.size(); i += 2) {
            try {
                PayloadEntry errorSide = blindPayloads.get(i);
                PayloadEntry noErrorSide = blindPayloads.get(i + 1);

                HttpRequestResponse errorResp = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(errorSide.getValue())));
                HttpRequestResponse noErrorResp = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(noErrorSide.getValue())));

                if (errorResp.response() == null || noErrorResp.response() == null) continue;

                if (DiffEngine.responsesDiffer(errorResp, noErrorResp)) {
                    return IssueHelper.buildIssue(
                            ISSUE_PREFIX + "Blind (Error-Based)",
                            "Error-based blind pair produced different responses.<br>"
                                    + "Error-side: <b>" + IssueHelper.escapeHtml(errorSide.getValue())
                                    + "</b> (status " + HttpHelper.statusCode(errorResp) + ")<br>"
                                    + "No-error: <b>" + IssueHelper.escapeHtml(noErrorSide.getValue())
                                    + "</b> (status " + HttpHelper.statusCode(noErrorResp) + ")<br>"
                                    + "Similarity: " + String.format("%.2f", DiffEngine.bodySimilarity(errorResp, noErrorResp))
                                    + IssueHelper.formatCveRefs(errorSide.getCveRefs()),
                            "Ensure user input is never interpolated into template expressions.",
                            url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM,
                            base, errorResp, noErrorResp);
                }
            } catch (Exception e) {
                api.logging().logToError("SstiCheck blind error: " + e.getMessage());
            }
        }
        return null;
    }

    private String attemptEngineIdentification(HttpRequestResponse response) {
        String body = HttpHelper.bodyToString(response).toLowerCase(Locale.ROOT);
        if (body.contains("jinja2") || body.contains("jinja")) return "Jinja2";
        if (body.contains("twig")) return "Twig";
        if (body.contains("freemarker")) return "Freemarker";
        if (body.contains("velocity")) return "Velocity";
        if (body.contains("pebble")) return "Pebble";
        if (body.contains("thymeleaf")) return "Thymeleaf";
        if (body.contains("smarty")) return "Smarty";
        if (body.contains("mako")) return "Mako";
        if (body.contains("handlebars")) return "Handlebars";
        if (body.contains("erb")) return "ERB";
        return "Generic";
    }

    private String matchExpectedResponse(HttpRequestResponse probe, String expectedResponse) {
        String body = HttpHelper.bodyToString(probe);
        if (body.isEmpty()) return null;

        for (String entry : expectedResponse.split(",")) {
            String trimmed = entry.trim();
            int eqIdx = trimmed.indexOf('=');
            if (eqIdx <= 0 || eqIdx >= trimmed.length() - 1) continue;
            String token = trimmed.substring(0, eqIdx);
            String engine = trimmed.substring(eqIdx + 1);
            if (body.contains(token)) return engine;
        }
        return null;
    }
}
