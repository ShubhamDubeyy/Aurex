package top10.ui;

import burp.api.montoya.MontoyaApi;
import top10.checks.CheckModule;
import top10.payloads.PayloadStore;
import top10.util.FindingsStore;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class MainTab {
    private final JPanel mainPanel;
    private final JTabbedPane tabbedPane;

    public MainTab(MontoyaApi api, List<CheckModule> modules, PayloadStore payloadStore, FindingsStore findingsStore) {
        mainPanel = new JPanel(new BorderLayout());
        tabbedPane = new JTabbedPane();

        // Create sub-tabs
        tabbedPane.addTab("Dashboard", new DashboardPanel(modules, findingsStore));
        tabbedPane.addTab("ORM Extractor", new OrmExtractorPanel(api, payloadStore));
        tabbedPane.addTab("SSRF Helper", new SsrfHelperPanel());
        tabbedPane.addTab("Payloads", new PayloadManagerPanel(payloadStore));
        tabbedPane.addTab("Findings", new FindingsPanel(findingsStore));

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    public String getTitle() {
        return "Aurex";
    }

    public Component getUiComponent() {
        return mainPanel;
    }
}
