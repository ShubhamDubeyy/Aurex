package top10.ui;

import top10.model.PayloadEntry;
import top10.payloads.PayloadStore;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Payload management panel providing filtering, inline editing, import/export,
 * and bulk-import capabilities. Backs the "Payloads" tab inside the main extension UI.
 */
public class PayloadManagerPanel extends JPanel {

    private static final String[] MODULES = {
            "All", "ssti", "orm", "nextjs", "unicode", "ssrf", "parser", "http2", "etag"
    };

    private static final String[] COLUMN_NAMES = {
            "Enabled", "Module", "Category", "Payload", "Description", "CVEs", "Source"
    };

    private final PayloadStore payloadStore;
    private final PayloadTableModel tableModel;
    private final JTable table;

    private final JComboBox<String> moduleFilter;
    private final JComboBox<String> categoryFilter;
    private final JTextField searchField;
    private final JLabel payloadCount;

    /** Currently displayed (filtered) payloads. */
    private List<PayloadEntry> filteredPayloads = new ArrayList<>();

    public PayloadManagerPanel(PayloadStore payloadStore) {
        super(new BorderLayout());
        this.payloadStore = payloadStore;

        // ================================================================
        // Top: filter bar
        // ================================================================
        JPanel filterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));

        filterBar.add(new JLabel("Module:"));
        moduleFilter = new JComboBox<>(MODULES);
        moduleFilter.addActionListener(e -> {
            updateCategoryFilter();
            applyFilters();
        });
        filterBar.add(moduleFilter);

        filterBar.add(new JLabel("Category:"));
        categoryFilter = new JComboBox<>(new String[]{"All"});
        categoryFilter.addActionListener(e -> applyFilters());
        filterBar.add(categoryFilter);

        filterBar.add(new JLabel("Search:"));
        searchField = new JTextField(18);
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                applyFilters();
            }
        });
        filterBar.add(searchField);

        payloadCount = new JLabel("");
        payloadCount.setFont(payloadCount.getFont().deriveFont(Font.BOLD, 11f));
        payloadCount.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        filterBar.add(payloadCount);

        add(filterBar, BorderLayout.NORTH);

        // ================================================================
        // Centre: table
        // ================================================================
        tableModel = new PayloadTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(22);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(55);  // Enabled
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);  // Module
        table.getColumnModel().getColumn(2).setPreferredWidth(100); // Category
        table.getColumnModel().getColumn(3).setPreferredWidth(320); // Payload
        table.getColumnModel().getColumn(4).setPreferredWidth(220); // Description
        table.getColumnModel().getColumn(5).setPreferredWidth(120); // CVEs
        table.getColumnModel().getColumn(6).setPreferredWidth(65);  // Source

        // Source column renderer
        table.getColumnModel().getColumn(6).setCellRenderer(new SourceCellRenderer());

        // Disabled-row renderer for non-boolean columns
        DefaultTableCellRenderer disabledRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tbl, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(tbl, value, isSelected, hasFocus, row, column);
                int modelRow = tbl.convertRowIndexToModel(row);
                if (modelRow >= 0 && modelRow < filteredPayloads.size()) {
                    PayloadEntry entry = filteredPayloads.get(modelRow);
                    if (!entry.isEnabled() && !isSelected) {
                        c.setForeground(Color.GRAY);
                    } else if (!isSelected) {
                        c.setForeground(tbl.getForeground());
                    }
                }
                return c;
            }
        };
        for (int col = 1; col <= 5; col++) {
            table.getColumnModel().getColumn(col).setCellRenderer(disabledRenderer);
        }

        // Double-click to edit
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int viewRow = table.getSelectedRow();
                    if (viewRow >= 0) {
                        int modelRow = table.convertRowIndexToModel(viewRow);
                        openEditDialog(modelRow);
                    }
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) {
                    return;
                }
                table.setRowSelectionInterval(viewRow, viewRow);
                int modelRow = table.convertRowIndexToModel(viewRow);
                showContextMenu(e.getComponent(), e.getX(), e.getY(), modelRow);
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        // ================================================================
        // Bottom: button toolbar
        // ================================================================
        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));

        JButton addBtn = new JButton("Add Payload");
        JButton editBtn = new JButton("Edit");
        JButton deleteBtn = new JButton("Delete");
        JButton importBtn = new JButton("Import JSON");
        JButton exportBtn = new JButton("Export JSON");
        JButton resetBtn = new JButton("Reset Module");
        JButton bulkBtn = new JButton("Bulk Import");

        addBtn.addActionListener(e -> openAddDialog());
        editBtn.addActionListener(e -> {
            int viewRow = table.getSelectedRow();
            if (viewRow >= 0) {
                openEditDialog(table.convertRowIndexToModel(viewRow));
            }
        });
        deleteBtn.addActionListener(e -> deleteSelected());
        importBtn.addActionListener(e -> doImportJson());
        exportBtn.addActionListener(e -> doExportJson());
        resetBtn.addActionListener(e -> doResetModule());
        bulkBtn.addActionListener(e -> doBulkImport());

        buttonBar.add(addBtn);
        buttonBar.add(editBtn);
        buttonBar.add(deleteBtn);
        buttonBar.add(Box.createHorizontalStrut(12));
        buttonBar.add(importBtn);
        buttonBar.add(exportBtn);
        buttonBar.add(Box.createHorizontalStrut(12));
        buttonBar.add(resetBtn);
        buttonBar.add(bulkBtn);

        add(buttonBar, BorderLayout.SOUTH);

        // Initial data load
        applyFilters();
    }

    // ------------------------------------------------------------------
    // Filtering
    // ------------------------------------------------------------------

    private void applyFilters() {
        String selectedModule = (String) moduleFilter.getSelectedItem();
        String selectedCategory = (String) categoryFilter.getSelectedItem();
        String search = searchField.getText().trim().toLowerCase();

        List<PayloadEntry> all = payloadStore.getAllPayloads();
        filteredPayloads = new ArrayList<>();

        for (PayloadEntry entry : all) {
            // Module filter
            if (selectedModule != null && !"All".equals(selectedModule)
                    && !selectedModule.equals(entry.getModule())) {
                continue;
            }

            // Category filter
            if (selectedCategory != null && !"All".equals(selectedCategory)
                    && !selectedCategory.equals(entry.getCategory())) {
                continue;
            }

            // Search filter
            if (!search.isEmpty()) {
                boolean matches = false;
                if (entry.getValue() != null && entry.getValue().toLowerCase().contains(search)) {
                    matches = true;
                }
                if (!matches && entry.getDescription() != null
                        && entry.getDescription().toLowerCase().contains(search)) {
                    matches = true;
                }
                if (!matches) {
                    String cveStr = String.join(", ", entry.getCveRefs());
                    if (cveStr.toLowerCase().contains(search)) {
                        matches = true;
                    }
                }
                if (!matches) {
                    continue;
                }
            }

            filteredPayloads.add(entry);
        }

        tableModel.fireTableDataChanged();
        updateCountLabel();
    }

    private void updateCategoryFilter() {
        String selectedModule = (String) moduleFilter.getSelectedItem();
        categoryFilter.removeAllItems();
        categoryFilter.addItem("All");

        List<PayloadEntry> pool;
        if (selectedModule == null || "All".equals(selectedModule)) {
            pool = payloadStore.getAllPayloads();
        } else {
            pool = payloadStore.getAll(selectedModule);
        }

        pool.stream()
                .map(PayloadEntry::getCategory)
                .distinct()
                .sorted()
                .forEach(categoryFilter::addItem);
    }

    private void updateCountLabel() {
        int shown = filteredPayloads.size();
        int total = payloadStore.getTotalCount();
        int userAdded = payloadStore.getUserAddedCount();
        payloadCount.setText(String.format("Showing %d of %d payloads (%d user-added)", shown, total, userAdded));
    }

    // ------------------------------------------------------------------
    // Context menu
    // ------------------------------------------------------------------

    private void showContextMenu(Component invoker, int x, int y, int modelRow) {
        if (modelRow < 0 || modelRow >= filteredPayloads.size()) {
            return;
        }
        PayloadEntry entry = filteredPayloads.get(modelRow);

        JPopupMenu menu = new JPopupMenu();

        JMenuItem toggle = new JMenuItem(entry.isEnabled() ? "Disable" : "Enable");
        toggle.addActionListener(e -> {
            payloadStore.toggleEnabled(entry.getId());
            applyFilters();
        });
        menu.add(toggle);

        JMenuItem duplicate = new JMenuItem("Duplicate");
        duplicate.addActionListener(e -> {
            PayloadEntry copy = entry.copy();
            payloadStore.addPayload(copy);
            applyFilters();
        });
        menu.add(duplicate);

        JMenuItem copyPayload = new JMenuItem("Copy Payload");
        copyPayload.addActionListener(e -> copyToClipboard(entry.getValue()));
        menu.add(copyPayload);

        if ("user".equals(entry.getAddedBy())) {
            menu.addSeparator();
            JMenuItem delete = new JMenuItem("Delete");
            delete.addActionListener(e -> {
                payloadStore.removePayload(entry.getId());
                applyFilters();
            });
            menu.add(delete);
        }

        menu.show(invoker, x, y);
    }

    private void copyToClipboard(String text) {
        if (text == null) {
            text = "";
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text), null);
    }

    // ------------------------------------------------------------------
    // Button actions
    // ------------------------------------------------------------------

    private void openAddDialog() {
        PayloadDialog dialog = new PayloadDialog(
                SwingUtilities.getWindowAncestor(this), "Add Payload", null);
        dialog.setVisible(true);
        PayloadEntry result = dialog.getResult();
        if (result != null) {
            payloadStore.addPayload(result);
            applyFilters();
        }
    }

    private void openEditDialog(int modelRow) {
        if (modelRow < 0 || modelRow >= filteredPayloads.size()) {
            return;
        }
        PayloadEntry existing = filteredPayloads.get(modelRow);
        PayloadDialog dialog = new PayloadDialog(
                SwingUtilities.getWindowAncestor(this), "Edit Payload", existing);
        dialog.setVisible(true);
        PayloadEntry result = dialog.getResult();
        if (result != null) {
            payloadStore.updatePayload(result);
            applyFilters();
        }
    }

    private void deleteSelected() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) {
            return;
        }
        int modelRow = table.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= filteredPayloads.size()) {
            return;
        }
        PayloadEntry entry = filteredPayloads.get(modelRow);
        if (!"user".equals(entry.getAddedBy())) {
            JOptionPane.showMessageDialog(this,
                    "Only user-added payloads can be deleted.",
                    "Cannot Delete", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this,
                "Delete this payload?", "Confirm Delete",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            payloadStore.removePayload(entry.getId());
            applyFilters();
        }
    }

    private void doImportJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import Payloads from JSON");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            payloadStore.importFromJson(chooser.getSelectedFile());
            applyFilters();
            JOptionPane.showMessageDialog(this,
                    "Import complete. Total payloads: " + payloadStore.getTotalCount(),
                    "Import Complete", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void doExportJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Payloads as JSON");
        chooser.setSelectedFile(new File("payloads.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            String selected = (String) moduleFilter.getSelectedItem();
            String moduleArg = (selected == null || "All".equals(selected)) ? null : selected;
            payloadStore.exportToJson(chooser.getSelectedFile(), moduleArg);
            JOptionPane.showMessageDialog(this,
                    "Export complete.", "Export Complete", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void doResetModule() {
        String selected = (String) moduleFilter.getSelectedItem();
        if (selected == null || "All".equals(selected)) {
            JOptionPane.showMessageDialog(this,
                    "Please select a specific module to reset.",
                    "No Module Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int confirm = JOptionPane.showConfirmDialog(this,
                "Reset all payloads for module \"" + selected + "\" to defaults?\n"
                        + "This will remove any user-added payloads for this module.",
                "Confirm Reset", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            payloadStore.resetToDefaults(selected);
            applyFilters();
        }
    }

    private void doBulkImport() {
        String selectedModule = (String) moduleFilter.getSelectedItem();
        if (selectedModule == null || "All".equals(selectedModule)) {
            JOptionPane.showMessageDialog(this,
                    "Please select a specific module before bulk importing.",
                    "No Module Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JPanel panel = new JPanel(new BorderLayout(6, 6));

        JPanel topFields = new JPanel(new GridLayout(1, 2, 6, 0));
        JTextField catField = new JTextField("general");
        topFields.add(new JLabel("Category:"));
        topFields.add(catField);
        panel.add(topFields, BorderLayout.NORTH);

        JTextArea textArea = new JTextArea(12, 40);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
        panel.add(new JLabel("Enter one payload per line:"), BorderLayout.SOUTH);

        int result = JOptionPane.showConfirmDialog(this, panel,
                "Bulk Import - " + selectedModule,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String category = catField.getText().trim();
            if (category.isEmpty()) {
                category = "general";
            }
            String[] lines = textArea.getText().split("\\n");
            int count = 0;
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    PayloadEntry entry = new PayloadEntry(selectedModule, category, trimmed, "");
                    payloadStore.addPayload(entry);
                    count++;
                }
            }
            applyFilters();
            JOptionPane.showMessageDialog(this,
                    "Imported " + count + " payloads into module \"" + selectedModule + "\".",
                    "Bulk Import Complete", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // ------------------------------------------------------------------
    // Table model
    // ------------------------------------------------------------------

    private class PayloadTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return filteredPayloads.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Class<?> getColumnClass(int column) {
            if (column == 0) {
                return Boolean.class;
            }
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0; // Only Enabled checkbox is editable
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            if (columnIndex == 0 && rowIndex >= 0 && rowIndex < filteredPayloads.size()) {
                PayloadEntry entry = filteredPayloads.get(rowIndex);
                payloadStore.toggleEnabled(entry.getId());
                fireTableCellUpdated(rowIndex, columnIndex);
                updateCountLabel();
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= filteredPayloads.size()) {
                return "";
            }
            PayloadEntry e = filteredPayloads.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> e.isEnabled();
                case 1 -> e.getModule();
                case 2 -> e.getCategory();
                case 3 -> truncate(e.getValue(), 60);
                case 4 -> e.getDescription();
                case 5 -> String.join(", ", e.getCveRefs());
                case 6 -> e.getAddedBy();
                default -> "";
            };
        }

        private String truncate(String s, int maxLen) {
            if (s == null) {
                return "";
            }
            return s.length() <= maxLen ? s : s.substring(0, maxLen) + "...";
        }
    }

    // ------------------------------------------------------------------
    // Source column renderer
    // ------------------------------------------------------------------

    private static class SourceCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String source) {
                if ("default".equals(source)) {
                    c.setForeground(new Color(34, 139, 34)); // green
                } else if ("user".equals(source)) {
                    c.setForeground(new Color(30, 90, 210)); // blue
                } else {
                    c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    // ------------------------------------------------------------------
    // Add / Edit dialog
    // ------------------------------------------------------------------

    private static class PayloadDialog extends JDialog {
        private PayloadEntry result;

        private final JComboBox<String> moduleBox;
        private final JTextField categoryField;
        private final JTextArea payloadArea;
        private final JTextField descriptionField;
        private final JTextField cvesField;
        private final JTextField tagsField;

        /**
         * @param owner  parent window
         * @param title  dialog title
         * @param existing null for Add mode; non-null for Edit mode
         */
        PayloadDialog(Window owner, String title, PayloadEntry existing) {
            super(owner, title, ModalityType.APPLICATION_MODAL);
            setLayout(new BorderLayout(8, 8));
            setResizable(true);

            JPanel formPanel = new JPanel(new GridBagLayout());
            formPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 6, 10));
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(4, 4, 4, 4);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;

            // Module
            gbc.gridy = 0;
            gbc.gridx = 0;
            gbc.weightx = 0;
            formPanel.add(new JLabel("Module:"), gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            String[] editableModules = {"ssti", "orm", "nextjs", "unicode", "ssrf", "parser", "http2", "etag"};
            moduleBox = new JComboBox<>(editableModules);
            formPanel.add(moduleBox, gbc);

            // Category
            gbc.gridy = 1;
            gbc.gridx = 0;
            gbc.weightx = 0;
            formPanel.add(new JLabel("Category:"), gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            categoryField = new JTextField(20);
            formPanel.add(categoryField, gbc);

            // Payload
            gbc.gridy = 2;
            gbc.gridx = 0;
            gbc.weightx = 0;
            gbc.anchor = GridBagConstraints.NORTHWEST;
            formPanel.add(new JLabel("Payload:"), gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            gbc.weighty = 1.0;
            gbc.fill = GridBagConstraints.BOTH;
            payloadArea = new JTextArea(3, 30);
            payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            payloadArea.setLineWrap(true);
            formPanel.add(new JScrollPane(payloadArea), gbc);
            gbc.weighty = 0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.anchor = GridBagConstraints.WEST;

            // Description
            gbc.gridy = 3;
            gbc.gridx = 0;
            gbc.weightx = 0;
            formPanel.add(new JLabel("Description:"), gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            descriptionField = new JTextField(30);
            formPanel.add(descriptionField, gbc);

            // CVE References
            gbc.gridy = 4;
            gbc.gridx = 0;
            gbc.weightx = 0;
            formPanel.add(new JLabel("CVE References:"), gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            cvesField = new JTextField(30);
            formPanel.add(cvesField, gbc);

            // Tags
            gbc.gridy = 5;
            gbc.gridx = 0;
            gbc.weightx = 0;
            formPanel.add(new JLabel("Tags:"), gbc);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            tagsField = new JTextField(30);
            formPanel.add(tagsField, gbc);

            add(formPanel, BorderLayout.CENTER);

            // Buttons
            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
            JButton okBtn = new JButton("OK");
            JButton cancelBtn = new JButton("Cancel");

            okBtn.addActionListener(e -> onOk(existing));
            cancelBtn.addActionListener(e -> {
                result = null;
                dispose();
            });

            btnPanel.add(okBtn);
            btnPanel.add(cancelBtn);
            add(btnPanel, BorderLayout.SOUTH);

            // Pre-fill for edit mode
            if (existing != null) {
                moduleBox.setSelectedItem(existing.getModule());
                categoryField.setText(existing.getCategory());
                payloadArea.setText(existing.getValue());
                descriptionField.setText(existing.getDescription());
                cvesField.setText(String.join(", ", existing.getCveRefs()));
                tagsField.setText(String.join(", ", existing.getTags()));
            }

            setMinimumSize(new Dimension(500, 350));
            pack();
            setLocationRelativeTo(owner);
        }

        private void onOk(PayloadEntry existing) {
            String payloadValue = payloadArea.getText().trim();
            if (payloadValue.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Payload value cannot be empty.",
                        "Validation Error", JOptionPane.WARNING_MESSAGE);
                return;
            }

            String module = (String) moduleBox.getSelectedItem();
            String category = categoryField.getText().trim();
            if (category.isEmpty()) {
                category = "general";
            }

            if (existing != null) {
                // Edit mode: update the existing entry in-place
                result = existing.copy();
                result.setId(existing.getId());
                result.setAddedBy(existing.getAddedBy());
            } else {
                // Add mode: create a new user entry
                result = new PayloadEntry();
            }

            result.setModule(module);
            result.setCategory(category);
            result.setValue(payloadValue);
            result.setDescription(descriptionField.getText().trim());

            // Parse comma-separated CVEs
            String cvesText = cvesField.getText().trim();
            if (!cvesText.isEmpty()) {
                List<String> cves = Arrays.stream(cvesText.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toList());
                result.setCveRefs(cves);
            } else {
                result.setCveRefs(new ArrayList<>());
            }

            // Parse comma-separated tags
            String tagsText = tagsField.getText().trim();
            if (!tagsText.isEmpty()) {
                List<String> tags = Arrays.stream(tagsText.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toList());
                result.setTags(tags);
            } else {
                result.setTags(new ArrayList<>());
            }

            dispose();
        }

        PayloadEntry getResult() {
            return result;
        }
    }
}
