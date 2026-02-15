package top10.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public final class PayloadEntry {
    private String id;
    private String module;
    private String category;
    private String value;
    private String description;
    private List<String> cveRefs;
    private boolean enabled;
    private String addedBy; // "default" or "user"
    private List<String> tags;
    private String expectedResponse; // for engine-detect payloads

    public PayloadEntry() {
        this.id = UUID.randomUUID().toString();
        this.cveRefs = new ArrayList<>();
        this.tags = new ArrayList<>();
        this.enabled = true;
        this.addedBy = "user";
        this.description = "";
        this.expectedResponse = "";
    }

    public PayloadEntry(String module, String category, String value, String description) {
        this();
        this.module = Objects.requireNonNull(module);
        this.category = Objects.requireNonNull(category);
        this.value = Objects.requireNonNull(value);
        this.description = description != null ? description : "";
    }

    public static PayloadEntry defaultPayload(String module, String category, String value, String description) {
        PayloadEntry e = new PayloadEntry(module, category, value, description);
        e.addedBy = "default";
        return e;
    }

    public static PayloadEntry defaultPayload(String module, String category, String value, String description, String... cves) {
        PayloadEntry e = defaultPayload(module, category, value, description);
        for (String cve : cves) {
            e.cveRefs.add(cve);
        }
        return e;
    }

    public static PayloadEntry engineDetect(String module, String value, String expectedResponse, String description) {
        PayloadEntry e = defaultPayload(module, "engine-detect", value, description);
        e.expectedResponse = expectedResponse;
        return e;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getModule() { return module; }
    public void setModule(String module) { this.module = module; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public List<String> getCveRefs() { return Collections.unmodifiableList(cveRefs); }
    public void setCveRefs(List<String> cveRefs) { this.cveRefs = new ArrayList<>(cveRefs); }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getAddedBy() { return addedBy; }
    public void setAddedBy(String addedBy) { this.addedBy = addedBy; }
    public List<String> getTags() { return Collections.unmodifiableList(tags); }
    public void setTags(List<String> tags) { this.tags = new ArrayList<>(tags); }
    public String getExpectedResponse() { return expectedResponse; }
    public void setExpectedResponse(String expectedResponse) { this.expectedResponse = expectedResponse; }

    public PayloadEntry copy() {
        PayloadEntry copy = new PayloadEntry();
        copy.module = this.module;
        copy.category = this.category;
        copy.value = this.value;
        copy.description = this.description;
        copy.cveRefs = new ArrayList<>(this.cveRefs);
        copy.enabled = this.enabled;
        copy.addedBy = "user";
        copy.tags = new ArrayList<>(this.tags);
        copy.expectedResponse = this.expectedResponse;
        return copy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PayloadEntry p)) return false;
        return id.equals(p.id);
    }

    @Override
    public int hashCode() { return id.hashCode(); }
}
