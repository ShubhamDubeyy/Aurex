package top10.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public final class Finding {
    public enum Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO }
    public enum Confidence { CERTAIN, FIRM, TENTATIVE }

    private final String module;
    private final String name;
    private final Severity severity;
    private final Confidence confidence;
    private final String url;
    private final String parameter;
    private final String detail;
    private final String remediation;
    private final List<String> cveRefs;
    private final String timestamp;
    private boolean falsePositive;

    private Finding(Builder b) {
        this.module = b.module;
        this.name = b.name;
        this.severity = b.severity;
        this.confidence = b.confidence;
        this.url = b.url;
        this.parameter = b.parameter;
        this.detail = b.detail;
        this.remediation = b.remediation;
        this.cveRefs = List.copyOf(b.cveRefs);
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.falsePositive = false;
    }

    public String getModule() { return module; }
    public String getName() { return name; }
    public Severity getSeverity() { return severity; }
    public Confidence getConfidence() { return confidence; }
    public String getUrl() { return url; }
    public String getParameter() { return parameter; }
    public String getDetail() { return detail; }
    public String getRemediation() { return remediation; }
    public List<String> getCveRefs() { return cveRefs; }
    public String getTimestamp() { return timestamp; }
    public boolean isFalsePositive() { return falsePositive; }
    public void setFalsePositive(boolean fp) { this.falsePositive = fp; }

    public String getCveString() {
        return String.join(", ", cveRefs);
    }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String module = "";
        private String name = "";
        private Severity severity = Severity.INFO;
        private Confidence confidence = Confidence.TENTATIVE;
        private String url = "";
        private String parameter = "";
        private String detail = "";
        private String remediation = "";
        private final List<String> cveRefs = new ArrayList<>();

        public Builder module(String m) { this.module = m; return this; }
        public Builder name(String n) { this.name = n; return this; }
        public Builder severity(Severity s) { this.severity = s; return this; }
        public Builder confidence(Confidence c) { this.confidence = c; return this; }
        public Builder url(String u) { this.url = u; return this; }
        public Builder parameter(String p) { this.parameter = p; return this; }
        public Builder detail(String d) { this.detail = d; return this; }
        public Builder remediation(String r) { this.remediation = r; return this; }
        public Builder cve(String cve) { this.cveRefs.add(cve); return this; }
        public Builder cves(List<String> cves) { this.cveRefs.addAll(cves); return this; }
        public Finding build() { return new Finding(this); }
    }
}
