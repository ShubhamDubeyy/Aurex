package top10;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import top10.checks.*;
import top10.payloads.PayloadStore;
import top10.ui.MainTab;
import top10.util.FindingsStore;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;

public class Top10Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Aurex");

        api.logging().logToOutput("==================================================");
        api.logging().logToOutput("  Aurex");
        api.logging().logToOutput("  Developed by Shubham Dubey");
        api.logging().logToOutput("  GitHub:   https://github.com/ShubhamDubeyy/");
        api.logging().logToOutput("  LinkedIn: https://linkedin.com/in/shubham-dubeyy");
        api.logging().logToOutput("==================================================");
        api.logging().logToOutput("Loading...");

        // Initialize payload store (loads from disk or creates defaults)
        PayloadStore payloadStore = new PayloadStore();

        // Initialize findings store
        FindingsStore findingsStore = new FindingsStore();

        // Initialize all check modules
        List<CheckModule> modules = new ArrayList<>();
        modules.add(new SstiCheck(api, payloadStore));
        modules.add(new OrmLeakCheck(api, payloadStore));
        modules.add(new NextjsCacheCheck(api, payloadStore));
        modules.add(new UnicodeCheck(api, payloadStore));
        modules.add(new SsrfRedirectCheck(api, payloadStore));
        modules.add(new ParserDiffCheck(api, payloadStore));
        modules.add(new Http2ConnectCheck(api, payloadStore));
        modules.add(new EtagLeakCheck(api));

        // Register scan check
        Top10ScanCheck scanCheck = new Top10ScanCheck(api, modules, findingsStore);
        api.scanner().registerScanCheck(scanCheck);

        // Build UI on EDT
        try {
            SwingUtilities.invokeAndWait(() -> {
                MainTab mainTab = new MainTab(api, modules, payloadStore, findingsStore);
                api.userInterface().registerSuiteTab(mainTab.getTitle(), mainTab.getUiComponent());
            });
        } catch (Exception e) {
            api.logging().logToError("UI initialization error: " + e.getMessage());
        }

        api.logging().logToOutput("Aurex loaded! " + modules.size() + " modules, "
                + payloadStore.getTotalCount() + " payloads ready.");
    }
}
