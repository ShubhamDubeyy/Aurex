package top10.ui;

import top10.checks.CheckModule;
import top10.util.FindingsStore;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Dashboard panel showing module status, finding counts, and scan configuration.
 * Displayed as the first tab inside the main extension tab.
 */
public class DashboardPanel extends JPanel {

    private static final Map<String, String> MODULE_DESCRIPTIONS = new HashMap<>();

    static {
        MODULE_DESCRIPTIONS.put("SSTI", "Template injection detection across 44 engines");
        MODULE_DESCRIPTIONS.put("ORM Leak", "ORM filter operator abuse detection");
        MODULE_DESCRIPTIONS.put("Next.js Cache", "Cache poisoning & middleware bypass");
        MODULE_DESCRIPTIONS.put("Unicode Normalization", "NFKC/NFKD WAF bypass detection");
        MODULE_DESCRIPTIONS.put("SSRF Redirect", "Redirect chain & cloud metadata SSRF");
        MODULE_DESCRIPTIONS.put("Parser Differential", "JSON duplicate keys, method override, content-type confusion");
        MODULE_DESCRIPTIONS.put("HTTP/2 CONNECT", "HTTP/2 tunnel probe");
        MODULE_DESCRIPTIONS.put("ETag XS-Leak", "Cross-site ETag length leak preconditions");
    }

    private final List<CheckModule> modules;
    private final FindingsStore findingsStore;
    private final List<JLabel> findingCountLabels;

    public DashboardPanel(List<CheckModule> modules, FindingsStore findingsStore) {
        super(new BorderLayout());
        this.modules = modules;
        this.findingsStore = findingsStore;
        this.findingCountLabels = new ArrayList<>();

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        // --- Title section ---
        JLabel titleLabel = new JLabel("Aurex");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        contentPanel.add(titleLabel);

        JLabel authorLabel = new JLabel("by Shubham Dubey \u2014 github.com/ShubhamDubeyy");
        authorLabel.setFont(authorLabel.getFont().deriveFont(Font.PLAIN, 11f));
        authorLabel.setForeground(new Color(120, 120, 120));
        authorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        authorLabel.setBorder(new EmptyBorder(2, 0, 12, 0));
        contentPanel.add(authorLabel);

        // --- Module table section ---
        JPanel modulePanel = new JPanel(new GridBagLayout());
        modulePanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Modules",
                TitledBorder.LEFT, TitledBorder.TOP));
        modulePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Header row
        gbc.gridy = 0;
        gbc.gridx = 0;
        addHeaderLabel(modulePanel, gbc, "Enabled");
        gbc.gridx = 1;
        addHeaderLabel(modulePanel, gbc, "Module");
        gbc.gridx = 2;
        addHeaderLabel(modulePanel, gbc, "Status");
        gbc.gridx = 3;
        addHeaderLabel(modulePanel, gbc, "Findings");
        gbc.gridx = 4;
        gbc.weightx = 1.0;
        addHeaderLabel(modulePanel, gbc, "Description");
        gbc.weightx = 0;

        // One row per module
        for (int i = 0; i < modules.size(); i++) {
            CheckModule module = modules.get(i);
            gbc.gridy = i + 1;

            // Enable/disable checkbox
            gbc.gridx = 0;
            JCheckBox enabledBox = new JCheckBox();
            enabledBox.setSelected(module.isEnabled());
            enabledBox.addActionListener(e -> module.setEnabled(enabledBox.isSelected()));
            modulePanel.add(enabledBox, gbc);

            // Module name (bold)
            gbc.gridx = 1;
            JLabel nameLabel = new JLabel(module.getName());
            nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
            modulePanel.add(nameLabel, gbc);

            // Status indicator
            gbc.gridx = 2;
            JLabel statusLabel = new JLabel("Idle");
            statusLabel.setForeground(Color.GRAY);
            modulePanel.add(statusLabel, gbc);

            // Finding count
            gbc.gridx = 3;
            int count = findingsStore.getByModule(module.getName()).size();
            JLabel countLabel = new JLabel(String.valueOf(count));
            findingCountLabels.add(countLabel);
            modulePanel.add(countLabel, gbc);

            // Description
            gbc.gridx = 4;
            gbc.weightx = 1.0;
            String desc = MODULE_DESCRIPTIONS.getOrDefault(module.getName(), "");
            JLabel descLabel = new JLabel(desc);
            descLabel.setForeground(Color.DARK_GRAY);
            modulePanel.add(descLabel, gbc);
            gbc.weightx = 0;
        }

        contentPanel.add(modulePanel);
        contentPanel.add(Box.createVerticalStrut(12));

        // --- Scan Configuration section ---
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Scan Configuration",
                TitledBorder.LEFT, TitledBorder.TOP));
        configPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        GridBagConstraints cgbc = new GridBagConstraints();
        cgbc.insets = new Insets(4, 6, 4, 6);
        cgbc.anchor = GridBagConstraints.WEST;

        // Max requests per insertion point
        cgbc.gridy = 0;
        cgbc.gridx = 0;
        configPanel.add(new JLabel("Max requests per insertion point:"), cgbc);

        cgbc.gridx = 1;
        cgbc.fill = GridBagConstraints.HORIZONTAL;
        cgbc.weightx = 1.0;
        JSlider maxRequestsSlider = new JSlider(5, 50, 15);
        maxRequestsSlider.setMajorTickSpacing(5);
        maxRequestsSlider.setMinorTickSpacing(1);
        maxRequestsSlider.setPaintTicks(true);
        maxRequestsSlider.setPaintLabels(true);
        configPanel.add(maxRequestsSlider, cgbc);
        cgbc.weightx = 0;
        cgbc.fill = GridBagConstraints.NONE;

        cgbc.gridx = 2;
        JLabel sliderValueLabel = new JLabel(String.valueOf(maxRequestsSlider.getValue()));
        maxRequestsSlider.addChangeListener(e -> sliderValueLabel.setText(String.valueOf(maxRequestsSlider.getValue())));
        configPanel.add(sliderValueLabel, cgbc);

        // Only scan in-scope items
        cgbc.gridy = 1;
        cgbc.gridx = 0;
        cgbc.gridwidth = 3;
        JCheckBox inScopeOnly = new JCheckBox("Only scan in-scope items", true);
        configPanel.add(inScopeOnly, cgbc);

        // Skip static assets
        cgbc.gridy = 2;
        JCheckBox skipStatic = new JCheckBox("Skip static assets (.js, .css, images)", true);
        configPanel.add(skipStatic, cgbc);
        cgbc.gridwidth = 1;

        contentPanel.add(configPanel);
        contentPanel.add(Box.createVerticalStrut(12));

        // --- Refresh button ---
        JButton refreshButton = new JButton("Refresh Stats");
        refreshButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        refreshButton.addActionListener(e -> refreshStats());
        contentPanel.add(refreshButton);

        // Wrap everything in a scroll pane
        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Updates the finding count labels by re-reading from the findings store.
     */
    public void refreshStats() {
        SwingUtilities.invokeLater(() -> {
            for (int i = 0; i < modules.size() && i < findingCountLabels.size(); i++) {
                int count = findingsStore.getByModule(modules.get(i).getName()).size();
                findingCountLabels.get(i).setText(String.valueOf(count));
            }
        });
    }

    private void addHeaderLabel(JPanel panel, GridBagConstraints gbc, String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 12f));
        label.setForeground(new Color(80, 80, 80));
        panel.add(label, gbc);
    }
}
