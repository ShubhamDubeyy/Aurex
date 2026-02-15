package top10.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

public interface CheckModule {

    String getName();

    boolean isEnabled();

    void setEnabled(boolean enabled);

    List<AuditIssue> passiveAudit(HttpRequestResponse baseRequestResponse);

    List<AuditIssue> activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint);
}
