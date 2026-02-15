package top10.payloads;

import top10.model.PayloadEntry;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * Thread-safe, JSON-persisted payload store for the Burp Suite OWASP Top 10 scanner extension.
 * <p>
 * Payloads are stored in {@code ~/.burp_top10/payloads.json} and kept in sync with an in-memory
 * list. All access is guarded by a {@link ReentrantReadWriteLock} so the store is safe to use
 * from Burp's multiple threads (scan threads, UI thread, etc.).
 * <p>
 * If disk I/O fails at any point the store continues to operate with its in-memory state and
 * logs errors to {@code stderr}.
 */
public class PayloadStore {

    private static final String STORE_DIR = ".burp_top10";
    private static final String STORE_FILE = "payloads.json";

    private final Gson gson;
    private final ReentrantReadWriteLock lock;
    private final List<PayloadEntry> payloads;

    public PayloadStore() {
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.lock = new ReentrantReadWriteLock();
        this.payloads = new ArrayList<>();

        Path storePath = getStorePath();
        if (Files.exists(storePath)) {
            load();
        } else {
            // First run -- seed with built-in defaults and persist to disk
            payloads.addAll(DefaultPayloads.getAll());
            persist();
        }
    }

    // -----------------------------------------------------------------------
    // Public query methods
    // -----------------------------------------------------------------------

    /**
     * Returns all enabled payloads whose module AND category match the given values.
     */
    public List<PayloadEntry> getEnabled(String module, String category) {
        lock.readLock().lock();
        try {
            return payloads.stream()
                    .filter(PayloadEntry::isEnabled)
                    .filter(p -> module.equals(p.getModule()))
                    .filter(p -> category.equals(p.getCategory()))
                    .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns every payload (enabled and disabled) for the given module.
     */
    public List<PayloadEntry> getAll(String module) {
        lock.readLock().lock();
        try {
            return payloads.stream()
                    .filter(p -> module.equals(p.getModule()))
                    .collect(Collectors.toList());
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Returns a snapshot of every payload in the store.
     */
    public List<PayloadEntry> getAllPayloads() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(payloads);
        } finally {
            lock.readLock().unlock();
        }
    }

    // -----------------------------------------------------------------------
    // Public mutation methods
    // -----------------------------------------------------------------------

    /**
     * Adds a new payload entry and persists.
     */
    public void addPayload(PayloadEntry entry) {
        lock.writeLock().lock();
        try {
            payloads.add(entry);
            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Removes a payload by id. Only user-added payloads may be removed.
     */
    public void removePayload(String id) {
        lock.writeLock().lock();
        try {
            boolean removed = payloads.removeIf(p -> p.getId().equals(id) && "user".equals(p.getAddedBy()));
            if (removed) {
                persist();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Replaces an existing payload entry (matched by id) with the supplied entry and persists.
     */
    public void updatePayload(PayloadEntry entry) {
        lock.writeLock().lock();
        try {
            for (int i = 0; i < payloads.size(); i++) {
                if (payloads.get(i).getId().equals(entry.getId())) {
                    payloads.set(i, entry);
                    persist();
                    return;
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Toggles the {@code enabled} flag on the payload identified by {@code id}.
     */
    public void toggleEnabled(String id) {
        lock.writeLock().lock();
        try {
            for (PayloadEntry p : payloads) {
                if (p.getId().equals(id)) {
                    p.setEnabled(!p.isEnabled());
                    persist();
                    return;
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Imports payloads from an external JSON file. Entries whose {@code (value, module, category)}
     * combination already exists in the store are skipped; new entries are added. Persists after
     * the merge.
     */
    public void importFromJson(File file) {
        lock.writeLock().lock();
        try {
            PayloadEntry[] imported;
            try (Reader reader = new FileReader(file)) {
                imported = gson.fromJson(reader, PayloadEntry[].class);
            } catch (IOException e) {
                System.err.println("[PayloadStore] Failed to read import file: " + e.getMessage());
                return;
            }

            if (imported == null) {
                return;
            }

            boolean changed = false;
            for (PayloadEntry incoming : imported) {
                boolean duplicate = payloads.stream().anyMatch(existing ->
                        existing.getValue().equals(incoming.getValue())
                                && existing.getModule().equals(incoming.getModule())
                                && existing.getCategory().equals(incoming.getCategory()));
                if (!duplicate) {
                    payloads.add(incoming);
                    changed = true;
                }
            }

            if (changed) {
                persist();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Exports payloads to the given file. If {@code moduleFilter} is {@code null}, all payloads
     * are exported; otherwise only those matching the module.
     */
    public void exportToJson(File file, String moduleFilter) {
        lock.readLock().lock();
        try {
            List<PayloadEntry> toExport;
            if (moduleFilter == null) {
                toExport = new ArrayList<>(payloads);
            } else {
                toExport = payloads.stream()
                        .filter(p -> moduleFilter.equals(p.getModule()))
                        .collect(Collectors.toList());
            }

            try (Writer writer = new FileWriter(file)) {
                gson.toJson(toExport, writer);
            } catch (IOException e) {
                System.err.println("[PayloadStore] Failed to export payloads: " + e.getMessage());
            }
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Removes all payloads for the given module and replaces them with the built-in defaults
     * for that module. Persists after the reset.
     */
    public void resetToDefaults(String module) {
        lock.writeLock().lock();
        try {
            payloads.removeIf(p -> module.equals(p.getModule()));

            List<PayloadEntry> defaults = DefaultPayloads.getAll();
            for (PayloadEntry d : defaults) {
                if (module.equals(d.getModule())) {
                    payloads.add(d);
                }
            }

            persist();
        } finally {
            lock.writeLock().unlock();
        }
    }

    // -----------------------------------------------------------------------
    // Public count helpers
    // -----------------------------------------------------------------------

    public int getTotalCount() {
        lock.readLock().lock();
        try {
            return payloads.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    public int getUserAddedCount() {
        lock.readLock().lock();
        try {
            return (int) payloads.stream().filter(p -> "user".equals(p.getAddedBy())).count();
        } finally {
            lock.readLock().unlock();
        }
    }

    public int getEnabledCount() {
        lock.readLock().lock();
        try {
            return (int) payloads.stream().filter(PayloadEntry::isEnabled).count();
        } finally {
            lock.readLock().unlock();
        }
    }

    // -----------------------------------------------------------------------
    // Private persistence helpers
    // -----------------------------------------------------------------------

    /**
     * Loads the payload list from the JSON store file into memory, replacing any current contents.
     */
    private void load() {
        lock.writeLock().lock();
        try {
            Path storePath = getStorePath();
            try (Reader reader = Files.newBufferedReader(storePath)) {
                PayloadEntry[] entries = gson.fromJson(reader, PayloadEntry[].class);
                payloads.clear();
                if (entries != null) {
                    payloads.addAll(Arrays.asList(entries));
                }
            } catch (IOException e) {
                System.err.println("[PayloadStore] Failed to load payloads from disk: " + e.getMessage());
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Persists the current in-memory payload list to the JSON store file.
     * <p>
     * <b>Must be called while holding the write lock.</b>
     */
    private void persist() {
        Path storePath = getStorePath();
        try (Writer writer = Files.newBufferedWriter(storePath)) {
            gson.toJson(payloads, writer);
        } catch (IOException e) {
            System.err.println("[PayloadStore] Failed to persist payloads to disk: " + e.getMessage());
        }
    }

    /**
     * Returns the path to {@code ~/.burp_top10/payloads.json}, creating the parent directories
     * if they do not yet exist.
     */
    private Path getStorePath() {
        Path dir = Paths.get(System.getProperty("user.home"), STORE_DIR);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            System.err.println("[PayloadStore] Failed to create store directory: " + e.getMessage());
        }
        return dir.resolve(STORE_FILE);
    }
}
