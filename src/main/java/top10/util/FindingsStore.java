package top10.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import top10.model.Finding;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * Thread-safe collection of {@link Finding} instances with deduplication.
 * <p>
 * Duplicate detection is based on a composite key built from
 * {@code module | url | parameter | name}.
 */
public class FindingsStore {

    private static final String CSV_HEADER = "Timestamp,Module,Severity,Confidence,URL,Parameter,Detail,CVEs";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    private final List<Finding> findings = new CopyOnWriteArrayList<>();
    private final Set<String> dedupKeys = ConcurrentHashMap.newKeySet();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    /**
     * Add a finding if it is not a duplicate.
     *
     * @return {@code true} if the finding was added; {@code false} if a duplicate already existed
     */
    public boolean add(Finding finding) {
        String key = dedupKey(finding);
        if (dedupKeys.add(key)) {
            findings.add(finding);
            notifyListeners();
            return true;
        }
        return false;
    }

    /**
     * Return an unmodifiable snapshot of all findings.
     */
    public List<Finding> getAll() {
        return List.copyOf(findings);
    }

    /**
     * Return all findings whose module matches the given value.
     */
    public List<Finding> getByModule(String module) {
        return findings.stream()
                .filter(f -> f.getModule().equals(module))
                .collect(Collectors.toList());
    }

    /**
     * Return the total number of stored findings.
     */
    public int size() {
        return findings.size();
    }

    /**
     * Return the number of findings with the given severity.
     */
    public int countBySeverity(Finding.Severity severity) {
        return (int) findings.stream()
                .filter(f -> f.getSeverity() == severity)
                .count();
    }

    /**
     * Remove all findings and deduplication keys.
     */
    public void clear() {
        findings.clear();
        dedupKeys.clear();
        notifyListeners();
    }

    /**
     * Register a listener that will be invoked whenever the store changes
     * (finding added or store cleared).
     */
    public void addChangeListener(Runnable listener) {
        listeners.add(listener);
    }

    /**
     * Export all findings as a CSV string.
     */
    public String exportCsv() {
        StringBuilder sb = new StringBuilder();
        sb.append(CSV_HEADER).append('\n');
        for (Finding f : findings) {
            sb.append(escapeCsv(f.getTimestamp())).append(',');
            sb.append(escapeCsv(f.getModule())).append(',');
            sb.append(escapeCsv(f.getSeverity().name())).append(',');
            sb.append(escapeCsv(f.getConfidence().name())).append(',');
            sb.append(escapeCsv(f.getUrl())).append(',');
            sb.append(escapeCsv(f.getParameter())).append(',');
            sb.append(escapeCsv(f.getDetail())).append(',');
            sb.append(escapeCsv(f.getCveString()));
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * Export all findings as a JSON string (pretty-printed).
     */
    public String exportJson() {
        return GSON.toJson(findings);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private void notifyListeners() {
        for (Runnable listener : listeners) {
            listener.run();
        }
    }

    private static String dedupKey(Finding finding) {
        return finding.getModule() + "|"
                + finding.getUrl() + "|"
                + finding.getParameter() + "|"
                + finding.getName();
    }

    /**
     * Escape a value for inclusion in a CSV cell.  Values that contain commas,
     * double-quotes, or newlines are wrapped in double-quotes, with any
     * embedded double-quotes doubled.
     */
    private static String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
