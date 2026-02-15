package top10.model;

import java.util.Objects;

public final class CveReference {
    private final String id;
    private final String description;
    private final String url;

    public CveReference(String id, String description) {
        this.id = Objects.requireNonNull(id);
        this.description = description != null ? description : "";
        this.url = "https://nvd.nist.gov/vuln/detail/" + id;
    }

    public CveReference(String id) {
        this(id, "");
    }

    public String getId() { return id; }
    public String getDescription() { return description; }
    public String getUrl() { return url; }

    @Override
    public String toString() { return id; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CveReference c)) return false;
        return id.equals(c.id);
    }

    @Override
    public int hashCode() { return id.hashCode(); }
}
