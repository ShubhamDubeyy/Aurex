package top10.ui;

import top10.model.Finding;
import top10.util.FindingsStore;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Findings table panel with severity-coloured rows, context-menu actions,
 * and CSV/JSON export. Listens to the {@link FindingsStore} for live updates.
 */
public class FindingsPanel extends JPanel {

    private static final String[] COLUMN_NAMES = {
            "Timestamp", "Module", "Severity", "Confidence", "URL", "Parameter", "Detail", "CVEs"
    };

    private final FindingsStore findingsStore;
    private final FindingsTableModel tableModel;
    private final JTable table;
    private final JLabel findingsCount;

    public FindingsPanel(FindingsStore findingsStore) {
        super(new BorderLayout());
        this.findingsStore = findingsStore;

        // ---- Top: status bar ----
        findingsCount = new JLabel(buildCountText());
        findingsCount.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        findingsCount.setFont(findingsCount.getFont().deriveFont(Font.BOLD, 12f));
        add(findingsCount, BorderLayout.NORTH);

        // ---- Centre: table ----
        tableModel = new FindingsTableModel();
        table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Default column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(140); // Timestamp
        table.getColumnModel().getColumn(1).setPreferredWidth(110); // Module
        table.getColumnModel().getColumn(2).setPreferredWidth(80);  // Severity
        table.getColumnModel().getColumn(3).setPreferredWidth(90);  // Confidence
        table.getColumnModel().getColumn(4).setPreferredWidth(300); // URL
        table.getColumnModel().getColumn(5).setPreferredWidth(100); // Parameter
        table.getColumnModel().getColumn(6).setPreferredWidth(300); // Detail
        table.getColumnModel().getColumn(7).setPreferredWidth(140); // CVEs

        // Sortable columns
        TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        // Severity colour renderer
        table.getColumnModel().getColumn(2).setCellRenderer(new SeverityCellRenderer());

        // Right-click context menu
        table.addMouseListener(new MouseAdapter() {
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

        // ---- Bottom: button panel ----
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        JButton exportCsv = new JButton("Export CSV");
        JButton exportJson = new JButton("Export JSON");
        JButton clearAll = new JButton("Clear All");

        exportCsv.addActionListener(e -> doExportCsv());
        exportJson.addActionListener(e -> doExportJson());
        clearAll.addActionListener(e -> doClearAll());

        buttonPanel.add(exportCsv);
        buttonPanel.add(exportJson);
        buttonPanel.add(clearAll);
        add(buttonPanel, BorderLayout.SOUTH);

        // ---- Auto-refresh via change listener ----
        findingsStore.addChangeListener(() -> SwingUtilities.invokeLater(this::refreshTable));
    }

    // ------------------------------------------------------------------
    // Public refresh method
    // ------------------------------------------------------------------

    public void refreshTable() {
        tableModel.refresh();
        findingsCount.setText(buildCountText());
    }

    // ------------------------------------------------------------------
    // Status text helper
    // ------------------------------------------------------------------

    private String buildCountText() {
        int total = findingsStore.size();
        int crit = findingsStore.countBySeverity(Finding.Severity.CRITICAL);
        int high = findingsStore.countBySeverity(Finding.Severity.HIGH);
        int med = findingsStore.countBySeverity(Finding.Severity.MEDIUM);
        int low = findingsStore.countBySeverity(Finding.Severity.LOW);
        int info = findingsStore.countBySeverity(Finding.Severity.INFO);
        return String.format("%d findings (%d Critical, %d High, %d Medium, %d Low, %d Info)",
                total, crit, high, med, low, info);
    }

    // ------------------------------------------------------------------
    // Context menu
    // ------------------------------------------------------------------

    private void showContextMenu(Component invoker, int x, int y, int modelRow) {
        List<Finding> findings = findingsStore.getAll();
        if (modelRow < 0 || modelRow >= findings.size()) {
            return;
        }
        Finding finding = findings.get(modelRow);

        JPopupMenu menu = new JPopupMenu();

        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> copyToClipboard(finding.getUrl()));
        menu.add(copyUrl);

        JMenuItem copyDetail = new JMenuItem("Copy Detail");
        copyDetail.addActionListener(e -> copyToClipboard(finding.getDetail()));
        menu.add(copyDetail);

        JMenuItem copyCves = new JMenuItem("Copy CVEs");
        copyCves.addActionListener(e -> copyToClipboard(finding.getCveString()));
        menu.add(copyCves);

        menu.addSeparator();

        String fpLabel = finding.isFalsePositive() ? "Unmark False Positive" : "Mark as False Positive";
        JMenuItem toggleFp = new JMenuItem(fpLabel);
        toggleFp.addActionListener(e -> {
            finding.setFalsePositive(!finding.isFalsePositive());
            refreshTable();
        });
        menu.add(toggleFp);

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
    // Export / Clear actions
    // ------------------------------------------------------------------

    private void doExportCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Findings as CSV");
        chooser.setSelectedFile(new File("findings.csv"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter writer = new FileWriter(chooser.getSelectedFile())) {
                writer.write(findingsStore.exportCsv());
                JOptionPane.showMessageDialog(this,
                        "Exported " + findingsStore.size() + " findings to CSV.",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to write CSV: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void doExportJson() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export Findings as JSON");
        chooser.setSelectedFile(new File("findings.json"));
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter writer = new FileWriter(chooser.getSelectedFile())) {
                writer.write(findingsStore.exportJson());
                JOptionPane.showMessageDialog(this,
                        "Exported " + findingsStore.size() + " findings to JSON.",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to write JSON: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void doClearAll() {
        int confirm = JOptionPane.showConfirmDialog(this,
                "Clear all " + findingsStore.size() + " findings? This cannot be undone.",
                "Confirm Clear", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            findingsStore.clear();
            refreshTable();
        }
    }

    // ------------------------------------------------------------------
    // Table model
    // ------------------------------------------------------------------

    private class FindingsTableModel extends AbstractTableModel {
        private List<Finding> data = new ArrayList<>(findingsStore.getAll());

        public void refresh() {
            data = new ArrayList<>(findingsStore.getAll());
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return data.size();
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
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= data.size()) {
                return "";
            }
            Finding f = data.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> f.getTimestamp();
                case 1 -> f.getModule();
                case 2 -> f.getSeverity().name();
                case 3 -> f.getConfidence().name();
                case 4 -> f.getUrl();
                case 5 -> f.getParameter();
                case 6 -> f.getDetail();
                case 7 -> f.getCveString();
                default -> "";
            };
        }
    }

    // ------------------------------------------------------------------
    // Custom severity cell renderer
    // ------------------------------------------------------------------

    private static class SeverityCellRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && value instanceof String severityStr) {
                try {
                    Finding.Severity severity = Finding.Severity.valueOf(severityStr);
                    c.setForeground(colorForSeverity(severity));
                } catch (IllegalArgumentException ignored) {
                    c.setForeground(table.getForeground());
                }
            } else if (!isSelected) {
                c.setForeground(table.getForeground());
            }

            setFont(getFont().deriveFont(Font.BOLD));
            return c;
        }

        private static Color colorForSeverity(Finding.Severity severity) {
            return switch (severity) {
                case CRITICAL -> new Color(220, 20, 20);
                case HIGH -> new Color(255, 140, 0);
                case MEDIUM -> new Color(200, 200, 0);
                case LOW -> new Color(70, 130, 180);
                case INFO -> Color.GRAY;
            };
        }
    }
}
