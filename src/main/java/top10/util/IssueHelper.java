package top10.util;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

public final class IssueHelper {

    private IssueHelper() {}

    public static String escapeHtml(String input) {
        if (input == null) return "";
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    public static String formatCveRefs(List<String> cveRefs) {
        if (cveRefs == null || cveRefs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder("<br><br><b>CVE References:</b> ");
        for (int i = 0; i < cveRefs.size(); i++) {
            if (i > 0) sb.append(", ");
            String cve = escapeHtml(cveRefs.get(i));
            sb.append("<a href=\"https://nvd.nist.gov/vuln/detail/")
              .append(cve).append("\">").append(cve).append("</a>");
        }
        return sb.toString();
    }

    public static AuditIssue buildIssue(String name, String detail, String remediation,
            String url, AuditIssueSeverity severity, AuditIssueConfidence confidence,
            HttpRequestResponse... evidence) {
        return AuditIssue.auditIssue(name, detail, remediation, url, severity, confidence,
                null, null, severity, evidence);
    }
}
