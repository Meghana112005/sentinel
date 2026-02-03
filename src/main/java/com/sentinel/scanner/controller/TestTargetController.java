package com.sentinel.scanner.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test-target")
public class TestTargetController {

    /**
     * Serves a page containing forms for the scanner to find.
     */
    @GetMapping(produces = MediaType.TEXT_HTML_VALUE)
    public String landingPage() {
        return "<html>" +
                "<head><title>Vulnerable Test Target</title></head>" +
                "<body>" +
                "<h1>Vulnerable Scan Target</h1>" +
                "<p>This page exists to test the scanner.</p>" +

                "<h2>1. SQL Injection Login Form</h2>" +
                "<form action='/test-target/login' method='POST'>" +
                "  Username: <input type='text' name='username'><br>" +
                "  Password: <input type='password' name='password'><br>" +
                "  <input type='submit' value='Login'>" +
                "</form>" +

                "<h2>2. XSS Search Form</h2>" +
                "<form action='/test-target/search' method='GET'>" +
                "  Search: <input type='text' name='query'><br>" +
                "  <input type='submit' value='Search'>" +
                "</form>" +

                "</body>" +
                "</html>";
    }

    /**
     * Serves valid/secure page for comparison
     */
    @GetMapping(value = "/secure", produces = MediaType.TEXT_HTML_VALUE)
    public String securePage() {
        return "<html>" +
                "<head><title>Secure Test Target</title></head>" +
                "<body>" +
                "<h1>Secure Scan Target</h1>" +
                "<p>This page simulates a secure application.</p>" +

                "<h2>1. Secure Login Form</h2>" +
                "<form action='/test-target/secure/login' method='POST'>" +
                "  Username: <input type='text' name='username'><br>" +
                "  Password: <input type='password' name='password'><br>" +
                "  <input type='submit' value='Login'>" +
                "</form>" +

                "<h2>2. Secure Search Form</h2>" +
                "<form action='/test-target/secure/search' method='GET'>" +
                "  Search: <input type='text' name='query'><br>" +
                "  <input type='submit' value='Search'>" +
                "</form>" +

                "</body>" +
                "</html>";
    }

    /**
     * Simulates a SQL Injection Vulnerability.
     * - Returns SQL error if single quote is used.
     * - Sleeps if SLEEP(5) is used.
     * - Returns Boolean differences.
     */
    @PostMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    public String login(@RequestParam(required = false) String username,
            @RequestParam(required = false) String password) {

        String input = (username != null) ? username : "";
        input = input.toLowerCase();

        // 1. Time-Based Simulation
        if (input.contains("sleep(5)") || input.contains("waitfor delay")) {
            try {
                Thread.sleep(5000); // Simulate DB delay
            } catch (InterruptedException e) {
                // Ignore
            }
            return "Login Failed (DB Timeout)";
        }

        // 2. Error-Based Simulation
        if (input.contains("'")) {
            return "<html><body>" +
                    "<h2>System Error</h2>" +
                    "<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"
                    + input + "' at line 1</p>" +
                    "</body></html>";
        }

        // 3. Boolean Detection Simulation
        // If they send 1=1 (True), we behave differently than 1=2 (False)
        if (input.contains("1=1")) {
            return "Logged in as Admin (Bypassed)";
        }

        return "Invalid credentials";
    }

    /**
     * SECURE Login Implementation
     */
    @PostMapping(value = "/secure/login", produces = MediaType.TEXT_HTML_VALUE)
    public String secureLogin(@RequestParam(required = false) String username,
            @RequestParam(required = false) String password) {

        // Simulates a secure backend using PreparedStatement (no SQLi possible)
        // We just return "Invalid credentials" regardless of quotes or 1=1
        return "Invalid credentials";
    }

    /**
     * Simulates Reflected XSS.
     * Simply echoes the input back without escaping.
     */
    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    public String search(@RequestParam(required = false) String query) {
        if (query == null)
            query = "";

        // VULNERABLE: Direct reflection of input
        return "<html><body>" +
                "<h1>Search Results</h1>" +
                "<p>You searched for: " + query + "</p>" +
                "<p>No results found.</p>" +
                "</body></html>";
    }

    /**
     * SECURE Search Implementation
     */
    @GetMapping(value = "/secure/search", produces = MediaType.TEXT_HTML_VALUE)
    public String secureSearch(@RequestParam(required = false) String query) {
        if (query == null)
            query = "";

        // SECURE: We escape the output
        String escaped = query.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");

        return "<html><body>" +
                "<h1>Search Results</h1>" +
                "<p>You searched for: " + escaped + "</p>" +
                "<p>No results found.</p>" +
                "</body></html>";
    }

    /**
     * ADVANCED Vulnerabilities Page - New Kind of vulnerabilities
     */
    @GetMapping(value = "/advanced", produces = MediaType.TEXT_HTML_VALUE)
    public String advancedPage() {
        return "<html>" +
                "<head><title>Advanced Vulnerabilities</title></head>" +
                "<body>" +
                "<h1>Advanced Targets</h1>" +

                "<h2>1. Command Injection Ping Service</h2>" +
                "<form action='/test-target/advanced/ping' method='POST'>" +
                "  IP Address: <input type='text' name='ip'><br>" +
                "  <input type='submit' value='Ping'>" +
                "</form>" +

                "<h2>2. Stored XSS Simulation</h2>" +
                "<form action='/test-target/advanced/comment' method='POST'>" +
                "  Comment: <textarea name='comment'></textarea><br>" +
                "  <input type='submit' value='Post Comment'>" +
                "</form>" +

                "<h2>3. DOM XSS Testing</h2>" +
                "<p>This page reads URL fragments. Try appending #<script>...</p>" +
                "<div id='output'></div>" +
                "<script>" +
                "  var hash = decodeURIComponent(window.location.hash.substring(1));" +
                "  if(hash) document.getElementById('output').innerHTML = hash;" +
                "</script>" +

                "<h2>4. Path Traversal Target</h2>" +
                "<form action='/test-target/advanced/file' method='GET'>" +
                "  Filename: <input type='text' name='path'><br>" +
                "  <input type='submit' value='Read File'>" +
                "</form>" +

                "<h2>5. SSTI Target</h2>" +
                "<form action='/test-target/advanced/template' method='GET'>" +
                "  Template Name: <input type='text' name='name'><br>" +
                "  <input type='submit' value='Render'>" +
                "</form>" +

                "<h2>6. Open Redirect Target</h2>" +
                "<form action='/test-target/advanced/redirect' method='GET'>" +
                "  Redirect URL: <input type='text' name='url'><br>" +
                "  <input type='submit' value='Go'>" +
                "</form>" +

                "</body>" +
                "</html>";
    }

    /**
     * Command Injection Simulation
     */
    @PostMapping(value = "/advanced/ping", produces = MediaType.TEXT_HTML_VALUE)
    public String ping(@RequestParam(required = false) String ip) {
        if (ip == null)
            ip = "";

        // Simulates finding command separators
        if (ip.contains(";") || ip.contains("|") || ip.contains("&&")) {
            return "<html><body>INJECTED_EXECUTION: Pinging 8.8.8.8<br>root:x:0:0:root...</body></html>";
        }
        return "Ping result for " + ip;
    }

    @PostMapping(value = "/advanced/comment", produces = MediaType.TEXT_HTML_VALUE)
    public String comment(@RequestParam(required = false) String comment) {
        // In a real app this would save to DB. Here we just reflect it pretending it
        // was stored.
        return "<html><body><h1>Comment Posted</h1><div class='comment'>" + comment + "</div></body></html>";
    }

    /**
     * 4. Path Traversal Simulation
     */
    @GetMapping(value = "/advanced/file", produces = MediaType.TEXT_PLAIN_VALUE)
    public String file(@RequestParam(required = false) String path) {
        if (path == null)
            path = "";

        // Simulates accessing sensitive files
        if (path.contains("../") || path.contains("..\\")) {
            if (path.contains("passwd")) {
                return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
            }
            if (path.contains("win.ini")) {
                return "[fonts]\nfor 16-bit app support\n[extensions]";
            }
        }
        return "File content for: " + path;
    }

    /**
     * 5. Server Side Template Injection (SSTI) Simulation
     */
    @GetMapping(value = "/advanced/template", produces = MediaType.TEXT_HTML_VALUE)
    public String template(@RequestParam(required = false) String name) {
        if (name == null)
            name = "";

        // Simulates engine evaluating 7*7
        if (name.contains("${7*7}") || name.contains("{{7*7}}")) {
            return "<html><body>Hello 49</body></html>";
        }
        return "<html><body>Hello " + name + "</body></html>";
    }

    /**
     * 6. Open Redirect Simulation
     */
    @GetMapping(value = "/advanced/redirect")
    public String redirect(@RequestParam(required = false) String url,
            javax.servlet.http.HttpServletResponse response) {
        if (url != null && !url.isEmpty()) {
            response.setHeader("Location", url);
            response.setStatus(302);
            return null;
        }
        return "No redirect";
    }
}
