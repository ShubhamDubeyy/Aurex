package top10;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import top10.checks.CheckModule;
import top10.model.Finding;
import top10.util.FindingsStore;
import top10.util.HttpHelper;

import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("deprecation")
public class Top10ScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final List<CheckModule> modules;
    private final FindingsStore findingsStore;

    public Top10ScanCheck(MontoyaApi api, List<CheckModule> modules, FindingsStore findingsStore) {
        this.api = api;
        this.modules = modules;
        this.findingsStore = findingsStore;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> allIssues = new ArrayList<>();

        if (HttpHelper.isStaticAsset(baseRequestResponse.request())) {
            return AuditResult.auditResult(allIssues);
        }

        for (CheckModule module : modules) {
            if (!module.isEnabled()) continue;
            try {
                List<AuditIssue> issues = module.activeAudit(baseRequestResponse, insertionPoint);
                if (issues != null && !issues.isEmpty()) {
                    allIssues.addAll(issues);
                    recordFindings(module.getName(), issues);
                }
            } catch (Exception e) {
                api.logging().logToError("[" + module.getName() + "] Active audit error: " + e.getMessage());
            }
        }
        return AuditResult.auditResult(allIssues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        List<AuditIssue> allIssues = new ArrayList<>();

        if (HttpHelper.isStaticAsset(baseRequestResponse.request())) {
            return AuditResult.auditResult(allIssues);
        }

        for (CheckModule module : modules) {
            if (!module.isEnabled()) continue;
            try {
                List<AuditIssue> issues = module.passiveAudit(baseRequestResponse);
                if (issues != null && !issues.isEmpty()) {
                    allIssues.addAll(issues);
                    recordFindings(module.getName(), issues);
                }
            } catch (Exception e) {
                api.logging().logToError("[" + module.getName() + "] Passive audit error: " + e.getMessage());
            }
        }
        return AuditResult.auditResult(allIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (existingIssue.name().equals(newIssue.name()) &&
            existingIssue.baseUrl().equals(newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    private void recordFindings(String moduleName, List<AuditIssue> issues) {
        for (AuditIssue issue : issues) {
            findingsStore.add(Finding.builder()
                    .module(moduleName)
                    .name(issue.name())
                    .severity(mapSeverity(issue.severity()))
                    .confidence(mapConfidence(issue.confidence()))
                    .url(issue.baseUrl())
                    .detail(issue.detail())
                    .build());
        }
    }

    private Finding.Severity mapSeverity(AuditIssueSeverity s) {
        return switch (s) {
            case HIGH -> Finding.Severity.HIGH;
            case MEDIUM -> Finding.Severity.MEDIUM;
            case LOW -> Finding.Severity.LOW;
            case INFORMATION -> Finding.Severity.INFO;
            default -> Finding.Severity.INFO;
        };
    }

    private Finding.Confidence mapConfidence(AuditIssueConfidence c) {
        return switch (c) {
            case CERTAIN -> Finding.Confidence.CERTAIN;
            case FIRM -> Finding.Confidence.FIRM;
            case TENTATIVE -> Finding.Confidence.TENTATIVE;
            default -> Finding.Confidence.TENTATIVE;
        };
    }
}
