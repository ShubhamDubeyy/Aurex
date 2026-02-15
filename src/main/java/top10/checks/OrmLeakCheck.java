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

public class OrmLeakCheck implements CheckModule {

    private static final String MODULE_NAME = "ORM Leak";
    private static final String PAYLOAD_MODULE = "orm";
    private static final String ISSUE_PREFIX = "[Top10-WHT] ORM Leak \u2014 ";

    private static final List<String> RELATIONAL_SENSITIVE_FIELDS = Arrays.asList("password", "token", "secret");

    private static final List<String> ORM_ERROR_MARKERS = Arrays.asList(
            "FieldError", "PrismaClientKnownRequestError", "ODataError", "Invalid filter", "Unknown field"
    );

    private static final List<String> PASSIVE_ERROR_SIGNATURES = Arrays.asList(
            "FieldError at", "Cannot resolve keyword", "PrismaClientKnownRequestError",
            "Invalid `prisma", "ODataException", "$filter", "Ransack",
            "ActiveRecord::StatementInvalid", "django.core.exceptions"
    );

    private static final double SENSITIVE_FIELD_THRESHOLD = 0.05;

    private final MontoyaApi api;
    private final PayloadStore payloadStore;
    private final HttpHelper httpHelper;
    private volatile boolean enabled;

    public OrmLeakCheck(MontoyaApi api, PayloadStore payloadStore) {
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

            for (String signature : PASSIVE_ERROR_SIGNATURES) {
                if (bodyLower.contains(signature.toLowerCase(Locale.ROOT))) {
                    issues.add(IssueHelper.buildIssue(
                            ISSUE_PREFIX + "Error Signature in Response",
                            "The response body contains an ORM error signature: <b>"
                                    + IssueHelper.escapeHtml(signature) + "</b>.",
                            "Suppress ORM error details in production. Implement field allowlists.",
                            url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE,
                            baseRequestResponse));
                    break;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("OrmLeakCheck passiveAudit error: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String url = baseRequestResponse.request().url();
            issues.addAll(testOrmDetectPayloads(baseRequestResponse, insertionPoint, url));
            issues.addAll(testSensitiveFields(baseRequestResponse, insertionPoint, url));
            issues.addAll(testRelationalTraversal(baseRequestResponse, insertionPoint, url));
        } catch (Exception e) {
            api.logging().logToError("OrmLeakCheck activeAudit error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testOrmDetectPayloads(HttpRequestResponse base, AuditInsertionPoint ip, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        List<PayloadEntry> payloads = payloadStore.getEnabled(PAYLOAD_MODULE, "orm-detect");

        for (PayloadEntry entry : payloads) {
            try {
                HttpRequestResponse probe = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(entry.getValue())));
                if (probe.response() == null) continue;

                boolean differs = DiffEngine.responsesDiffer(base, probe);
                boolean hasError = containsAnyOrmError(probe);

                if (differs && !hasError) {
                    String ormType = detectOrmType(entry);
                    issues.add(IssueHelper.buildIssue(
                            ISSUE_PREFIX + "Filter Accepted via " + ormType,
                            "The payload <b>" + IssueHelper.escapeHtml(entry.getValue())
                                    + "</b> was accepted as a filter (no error, response differs).<br>"
                                    + "ORM type: <b>" + IssueHelper.escapeHtml(ormType) + "</b><br>"
                                    + "Similarity: " + String.format("%.2f", DiffEngine.bodySimilarity(base, probe))
                                    + IssueHelper.formatCveRefs(entry.getCveRefs()),
                            "Implement a strict allowlist of filterable fields.",
                            url, AuditIssueSeverity.MEDIUM, AuditIssueConfidence.FIRM, base, probe));
                } else if (hasError) {
                    String ormType = detectOrmType(entry);
                    issues.add(IssueHelper.buildIssue(
                            ISSUE_PREFIX + "ORM Error Exposed via " + ormType,
                            "The payload <b>" + IssueHelper.escapeHtml(entry.getValue())
                                    + "</b> triggered an ORM error: <b>"
                                    + IssueHelper.escapeHtml(findMatchedOrmError(probe)) + "</b>"
                                    + IssueHelper.formatCveRefs(entry.getCveRefs()),
                            "Suppress ORM errors in production. Validate filter parameters.",
                            url, AuditIssueSeverity.LOW, AuditIssueConfidence.CERTAIN, base, probe));
                }
            } catch (Exception e) {
                api.logging().logToError("OrmLeakCheck orm-detect error: " + e.getMessage());
            }
        }
        return issues;
    }

    private List<AuditIssue> testSensitiveFields(HttpRequestResponse base, AuditInsertionPoint ip, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        List<PayloadEntry> fields = payloadStore.getEnabled(PAYLOAD_MODULE, "sensitive-fields");

        for (PayloadEntry entry : fields) {
            try {
                String field = entry.getValue();
                String probeA = field + "__startswith=a";
                String probeB = field + "__startswith=ZZZZNOTEXIST999";

                HttpRequestResponse respA = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(probeA)));
                HttpRequestResponse respB = httpHelper.sendRequest(
                        ip.buildHttpRequestWithPayload(ByteArray.byteArray(probeB)));

                if (respA.response() == null || respB.response() == null) continue;

                if (DiffEngine.lengthDiffers(respA, respB, SENSITIVE_FIELD_THRESHOLD)) {
                    issues.add(IssueHelper.buildIssue(
                            ISSUE_PREFIX + field + " Filterable via Django ORM",
                            "The field <b>" + IssueHelper.escapeHtml(field)
                                    + "</b> is filterable. Response delta: "
                                    + DiffEngine.lengthDelta(respA, respB) + " bytes."
                                    + IssueHelper.formatCveRefs(entry.getCveRefs()),
                            "Add " + IssueHelper.escapeHtml(field) + " to a denylist of non-filterable fields.",
                            url, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, base, respA, respB));
                }
            } catch (Exception e) {
                api.logging().logToError("OrmLeakCheck sensitive-field error: " + e.getMessage());
            }
        }
        return issues;
    }

    private List<AuditIssue> testRelationalTraversal(HttpRequestResponse base, AuditInsertionPoint ip, String url) {
        List<AuditIssue> issues = new ArrayList<>();
        List<PayloadEntry> prefixes = payloadStore.getEnabled(PAYLOAD_MODULE, "relational-prefixes");

        for (PayloadEntry prefixEntry : prefixes) {
            String prefix = prefixEntry.getValue();
            for (String field : RELATIONAL_SENSITIVE_FIELDS) {
                try {
                    String probeA = prefix + field + "__startswith=a";
                    String probeB = prefix + field + "__startswith=ZZZZNOTEXIST999";

                    HttpRequestResponse respA = httpHelper.sendRequest(
                            ip.buildHttpRequestWithPayload(ByteArray.byteArray(probeA)));
                    HttpRequestResponse respB = httpHelper.sendRequest(
                            ip.buildHttpRequestWithPayload(ByteArray.byteArray(probeB)));

                    if (respA.response() == null || respB.response() == null) continue;

                    if (DiffEngine.lengthDiffers(respA, respB, SENSITIVE_FIELD_THRESHOLD)) {
                        String path = prefix + field;
                        issues.add(IssueHelper.buildIssue(
                                ISSUE_PREFIX + path + " Filterable via Relational Traversal",
                                "The field <b>" + IssueHelper.escapeHtml(field)
                                        + "</b> is filterable via relational prefix <b>"
                                        + IssueHelper.escapeHtml(prefix) + "</b>. Delta: "
                                        + DiffEngine.lengthDelta(respA, respB) + " bytes."
                                        + IssueHelper.formatCveRefs(prefixEntry.getCveRefs()),
                                "Block relational traversal. Use explicit field allowlists.",
                                url, AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, base, respA, respB));
                    }
                } catch (Exception e) {
                    api.logging().logToError("OrmLeakCheck relational error: " + e.getMessage());
                }
            }
        }
        return issues;
    }

    private boolean containsAnyOrmError(HttpRequestResponse response) {
        for (String marker : ORM_ERROR_MARKERS) {
            if (HttpHelper.bodyContains(response, marker)) return true;
        }
        return false;
    }

    private String findMatchedOrmError(HttpRequestResponse response) {
        for (String marker : ORM_ERROR_MARKERS) {
            if (HttpHelper.bodyContains(response, marker)) return marker;
        }
        return "Unknown";
    }

    private String detectOrmType(PayloadEntry entry) {
        String value = entry.getValue().toLowerCase(Locale.ROOT);
        String desc = entry.getDescription().toLowerCase(Locale.ROOT);
        if (desc.contains("django") || value.contains("__startswith") || value.contains("__regex")) return "Django ORM";
        if (desc.contains("prisma") || value.contains("\"startswith\"") || value.contains("\"contains\"")) return "Prisma";
        if (desc.contains("odata") || value.contains("$filter") || value.contains("$orderby")) return "OData";
        if (desc.contains("ransack") || value.contains("q[")) return "Ransack (Rails)";
        if (desc.contains("harbor") || value.startsWith("q=")) return "Harbor";
        return "Unknown ORM";
    }
}
